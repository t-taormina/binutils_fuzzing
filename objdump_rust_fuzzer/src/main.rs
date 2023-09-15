use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Number of iterations to run per thread before reporting statistics
/// to the global statistics structure
const BATCH_SIZE: usize = 10;

#[derive(Default)]
struct Statistics {
    /// Number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    /// Number of crashes
    crashes: AtomicUsize,
}

struct Rng(u64);

impl Rng {
    // Create new random number generator
    fn new() -> Self {
        // Xor random seed with the current uptime of the processor in cycles
        Rng(0xe2bb33556b46e26 ^ unsafe { std::arch::x86_64::_rdtsc() })
    }

    // Generate a random number
    #[inline]
    fn rand(&mut self) -> usize {
        let val = self.0;
        // Xor shift random number generator(not good for hashing, great for fuzzing)
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val as usize
    }
}

/// Save 'inp' to disk with a unique filename based on 'thr_id' and run it
/// through 'objdump' once, returning the status code from 'objdump'
fn fuzz<P: AsRef<Path>>(filename: P, inp: &[u8]) -> io::Result<ExitStatus> {
    // Write out inp to temporary file
    fs::write(filename.as_ref(), inp)?;

    let runner = Command::new("/home/tylr/Fuzzing/binutils_fuzzing/binutils-2.14/binutils/objdump")
        .args(&["-x", filename.as_ref().to_str().unwrap()])
        .output()?;

    Ok(runner.status)
}

/// A fuzz worker that fuzzes forever in a loop
fn worker(thr_id: usize, statistics: Arc<Statistics>, corpus: Arc<Vec<Vec<u8>>>) -> io::Result<()> {
    // Create a random number generator
    let mut rng = Rng::new();

    let filename = format!("tmpinput_{}", thr_id);

    // Input for fuzz case
    let mut fuzz_input = Vec::new();

    loop {
        for _ in 0..BATCH_SIZE {
            // Pick a random index in bounds of corpus length
            let sel = rng.rand() % corpus.len();

            // Add random selection from corpus to fuzz_input
            fuzz_input.clear();
            fuzz_input.extend_from_slice(&corpus[sel]);

            // Corrupt fuzz input
            for _ in 0..(rng.rand() % 8) + 1 {
                let sel = rng.rand() % fuzz_input.len();
                fuzz_input[sel] = rng.rand() as u8;
            }

            let exit = fuzz(&filename, &fuzz_input)?;
            if let Some(11) = exit.signal() {
                //SIGSEGV
                statistics.crashes.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Update statistics
        statistics
            .fuzz_cases
            .fetch_add(BATCH_SIZE, Ordering::SeqCst);
    }
}

fn main() -> io::Result<()> {
    // Load the initial corpus
    // Use BTreeSet to deduplicate non-unique entries
    let mut corpus = BTreeSet::new();
    for filename in std::fs::read_dir("corpus")? {
        let filename = filename?.path();
        corpus.insert(std::fs::read(filename)?);
    }
    // Move unique corpus values into a vector
    let corpus: Arc<Vec<Vec<u8>>> = Arc::new(corpus.into_iter().collect());
    print!("Loaded {} files into corpus\n", corpus.len());
    // List of all running threads
    let mut threads = Vec::new();

    // Statistics during fuzzing
    let stats = Arc::new(Statistics::default());

    // Spawn threads
    for thr_id in 0..4 {
        // Add thread to list of threads
        let stats = stats.clone();
        let corpus = corpus.clone();
        threads.push(std::thread::spawn(move || worker(thr_id, stats, corpus)));
    }

    // Start a timer
    let start = Instant::now();

    loop {
        std::thread::sleep(Duration::from_millis(1000));

        // Compute and print stats
        let elapsed = start.elapsed().as_secs_f64();
        let cases = stats.fuzz_cases.load(Ordering::SeqCst);
        let crashes = stats.crashes.load(Ordering::SeqCst);
        let fcps = cases as f64 / elapsed;
        print!(
            "[{:10.6}] cases {:10} | fcps {:10.2} | crashes {:10}\n",
            elapsed, cases, fcps, crashes
        )
    }
}

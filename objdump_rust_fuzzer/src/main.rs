use std::fs;
use std::io;
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
}

/// Save 'inp' to disk with a unique filename based on 'thr_id' and run it
/// through 'objdump' once, returning the status code from 'objdump'
fn fuzz<P: AsRef<Path>>(filename: P, inp: &[u8]) -> io::Result<ExitStatus> {
    // Write out inp to temporary file
    fs::write(filename.as_ref(), inp)?;

    let runner = Command::new("./objdump")
        .args(&["-x", filename.as_ref().to_str().unwrap()])
        .output()?;

    Ok(runner.status)
}

/// A fuzz worker that fuzzes forever in a loop
fn worker(thr_id: usize, statistics: Arc<Statistics>) -> io::Result<()> {
    let filename = format!("tmpinput_{}", thr_id);
    loop {
        for _ in 0..BATCH_SIZE {
            fuzz(&filename, b"asdf")?;
        }
        statistics
            .fuzz_cases
            .fetch_add(BATCH_SIZE, Ordering::SeqCst);
    }
}

fn main() -> io::Result<()> {
    // List of all running threads
    let mut threads = Vec::new();

    // Statistics during fuzzing
    let stats = Arc::new(Statistics::default());

    // Spawn threads
    for thr_id in 0..4 {
        // Add thread to list of threads
        let stats = stats.clone();
        threads.push(std::thread::spawn(move || worker(thr_id, stats)));
    }

    // Start a timer
    let start = Instant::now();

    loop {
        std::thread::sleep(Duration::from_millis(1000));

        // Compute and print stats
        let elapsed = start.elapsed().as_secs_f64();
        let cases = stats.fuzz_cases.load(Ordering::SeqCst);
        let fcps = cases as f64 / elapsed;
        print!(
            "[{:10.6}] cases {:10} | fcps {:10.2}\n",
            elapsed, cases, fcps
        )
    }
}

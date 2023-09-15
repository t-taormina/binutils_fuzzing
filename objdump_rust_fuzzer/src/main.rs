use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

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
fn worker(thr_id: usize) -> io::Result<()> {
    Ok(())
}

fn main() -> io::Result<()> {
    // List of all running threads
    let mut threads = Vec::new();

    for thr_id in 0..4 {
        // Spawn the thread and add to list of threads
        threads.push(std::thread::spawn(move || worker(thr_id)));
    }

    for thr in threads {}
    print!("{:?}\n", fuzz("asdf", b"asdf")?);
    Ok(())
}

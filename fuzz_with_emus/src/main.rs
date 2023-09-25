/// Program drive for snapshot fuzzing using a RISC-V emulator that implements 
/// just the basic instructions. No atomics, multiplies, or divides

pub mod emulator;
pub mod mmu;
pub mod primitive;

use::std::sync::{Arc, Mutex};
use::std::time::{Duration, Instant};
use crate::emulator::{Emulator, Register, VmExit};
use crate::mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};

/// If `true` the guest writes to stdout and stdout and stderr will printed to
/// our own stdout and stderr
const VERBOSE_GUEST_PRINTS: bool = false;

fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}
/// Statistics during fuzzing
#[derive(Default)]
struct Statistics {
    /// Number of fuzz cases
    fuzz_cases: u64,

    /// Number of RISC-V instructions executed
    instrs_execed: u64,

    /// Total number of CPU cycles spent in the workers
    total_cycles: u64,

    /// Total number of CPU cycles spent resetting the guest
    reset_cycles: u64,

    /// Total number of CPU cycles spent emulating
    vm_cycles: u64,
}

fn worker(mut emu: Emulator, original: Arc<Emulator>,
          stats: Arc<Mutex<Statistics>>) {
    const BATCH_SIZE: usize = 10000;
    loop {
        // Start a timer
        let batch_start = rdtsc();

        let mut local_stats = Statistics::default();

        // Reset worker to original state
        for _ in 0..BATCH_SIZE {
            let it = rdtsc();
            emu.reset(&*original);
            local_stats.reset_cycles += rdtsc() - it;

            let _vmexit = loop {
                let it = rdtsc();
                let vmexit = emu.run(&mut local_stats.instrs_execed)
                    .expect_err("Failed to execute emulator");
                local_stats.vm_cycles += rdtsc() - it;

                match vmexit {
                    VmExit::Syscall => {
                        if let Err(vmexit) = handle_syscall(&mut emu) {
                            break vmexit;
                        }
                        let pc = emu.reg(Register::Pc);
                        emu.set_reg(Register::Pc, pc.wrapping_add(4));
                    }
                    _ => break vmexit,
                }
            };

            local_stats.fuzz_cases += 1;
        }

        // Get access to statistics
        let mut stats = stats.lock().unwrap();

        stats.fuzz_cases    += local_stats.fuzz_cases;
        stats.instrs_execed += local_stats.instrs_execed;
        stats.reset_cycles  += local_stats.reset_cycles;
        stats.vm_cycles     += local_stats.vm_cycles;

        // Compute amount of time during the batch
        let batch_elapsed    = rdtsc() - batch_start;
        stats.total_cycles  += batch_elapsed;
    }
}

fn handle_syscall(emu: &mut Emulator) -> Result<(), VmExit> {
    // Get the syscall number
    let num = emu.reg(Register::A7);

    match num {
        96 => {
            // set_tid_address(), just return the TID
            emu.set_reg(Register::A0, 1337);
            Ok(())
        }
        29 => {
            // ioctl()
            emu.set_reg(Register::A0, !0);
            Ok(())
        }
        66 => {
            //writev()
            let fd     = emu.reg(Register::A0);
            let iov    = emu.reg(Register::A1);
            let iovcnt = emu.reg(Register::A2);

            // We currently only handle stdout and stderr
            if fd != 1 && fd != 2 {
                // Return error
                emu.set_reg(Register::A0, !0);
                return Ok(());
            }

            let mut bytes_written = 0;

            for idx in 0..iovcnt {
                // Compute the pointer to the IO vector entry 
                // correspoinding to this index and validate that it 
                // will not overflow pointer size for the size of 
                // the '_iovec'
                let ptr = 16u64.checked_mul(idx)
                    .and_then(|x| x.checked_add(iov))
                    .and_then(|x| x.checked_add(15))
                    .ok_or(VmExit::SyscallIntegerOverflow)? as usize - 15;

                // Read the iovec entry pointer and length
                let buf: usize = emu.memory.read(VirtAddr(ptr + 0))?;
                let len: usize = emu.memory.read(VirtAddr(ptr + 8))?;

                // Look at the buffer
                let data = emu.memory.peek_perms(VirtAddr(buf), len,
                    Perm(PERM_READ))?;

                if VERBOSE_GUEST_PRINTS {
                    if let Ok(st) = core::str::from_utf8(data) {
                        print!("{}", st);
                    }
                }

                // Update number of bytes written
                bytes_written += len as u64;
            }

            // Return number of bytes written
            emu.set_reg(Register::A0, bytes_written);
            Ok(())
        }
        94 => {
            Err(VmExit::Exit)
        }
        _ => {
            panic!("unhandled syscall {}\n", num)
        }
    }
}

fn main() {
    let mut emu = Emulator::new(32 * 1024 * 1024);
    emu.memory
        .load(
            "./test_app",
            &[
                Section {
                    file_off: 0x0000000000000000,
                    virt_addr: VirtAddr(0x0000000000010000),
                    file_size: 0x0000000000000190,
                    mem_size: 0x0000000000000190,
                    permissions: Perm(PERM_READ),
                },
                Section {
                    file_off: 0x0000000000000190,
                    virt_addr: VirtAddr(0x0000000000011190),
                    file_size: 0x0000000000002284,
                    mem_size: 0x0000000000002284,
                    permissions: Perm(PERM_EXEC),
                },
                Section {
                    file_off: 0x0000000000002418,
                    virt_addr: VirtAddr(0x0000000000014418),
                    file_size: 0x0000000000000108,
                    mem_size: 0x0000000000000760,
                    permissions: Perm(PERM_READ | PERM_WRITE),
                },
            ],
        )
        .expect("Failed to load test application into address space");

    // Set the program entry point
    emu.set_reg(Register::Pc, 0x11190);

    // Setup a stack
    let stack = emu
        .memory
        .allocate(32 * 1024)
        .expect("Failed to allocate stack");
    emu.set_reg(Register::Sp, stack.0 as u64 + 32 * 1024);

    // Setup null terminated arg vectors
    let argv = emu.memory.allocate(8).expect("Failed to allocate argv");

    // Setup the program name
    emu.memory
        .write_from(argv, b"test\0")
        .expect("Failed to null terminate argv");

    macro_rules! push {
        ($expr:expr) => {
            let sp = 
                emu.reg(Register::Sp) - core::mem::size_of_val(&$expr)
                as u64;

            emu.memory
                .write(VirtAddr(sp as usize), $expr)
                .expect("Push failed");

            emu.set_reg(Register::Sp, sp);
        };
    }

    // Setup initial program stack state
    push!(0u64); // Auxp
    push!(0u64); // Envp
    push!(0u64); // Argv end
    push!(argv.0); // Argv
    push!(1u64); // Argc

    // Wrap the original emulator in an `Arc`
    let emu = Arc::new(emu);

    let stats = Arc::new(Mutex::new(Statistics::default()));
    
    // Change cores here
    let number_of_cores = 10;

    for _ in 0..number_of_cores {
        let new_emu = emu.fork();
        let stats   = stats.clone();
        let parent  = emu.clone();
        std::thread::spawn(move || {
            worker(new_emu, parent, stats);
        });
    }

    // Start a timer
    let start = Instant::now();

    let mut last_cases = 0;
    let mut last_instrs = 0;
    loop {
        std::thread::sleep(Duration::from_millis(1000));

        // Access stats structure
        let stats = stats.lock().unwrap();

        let elapsed    = start.elapsed().as_secs_f64();
        let fuzz_cases = stats.fuzz_cases;
        let instrs     = stats.instrs_execed;

        // Compute performance numbers
        let resetc = stats.reset_cycles as f64 / stats.total_cycles as f64;
        let vmc    = stats.vm_cycles    as f64 / stats.total_cycles as f64;

        print!("[{:10.4}] cases {:10} | fcps {:10} inst/sec {:10}\n\
                    reset {:8.4} | vm {:8.4}\n",
               elapsed, fuzz_cases, fuzz_cases - last_cases, 
               instrs - last_instrs, 
               resetc, vmc);

        last_cases = fuzz_cases;
        last_instrs = instrs;
    }
}

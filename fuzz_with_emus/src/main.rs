pub mod emulator;
pub mod mmu;
pub mod primitive;

use crate::emulator::{Emulator, Register};
use crate::mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};

fn main() {
    let mut emu = Emulator::new(32 * 1024 * 1024);
    emu.memory
        .load(
            "./test_app",
            &[
                Section {
                    file_off: 0x0000000000000040,
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

    // let tmp = emu.memory.allocate(4).unwrap();
    // emu.memory.write_from(tmp, b"asdf").unwrap();

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
            let sp = emu.reg(Register::Sp) - core::mem::size_of_val(&$expr) as u64;
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

    loop {
        let vmexit = emu.run().expect("Failed to execute emulator");

        match vmexit {
            emulator::VmExit::Syscall => {
                // Get the syscall number
                let num = emu.reg(Register::A7);

                match num {
                    96 => {
                        // set_tid_address(), just return the TID
                        emu.set_reg(Register::A0, 1337);
                    }
                    29 => {
                        // ioctl()
                        emu.set_reg(Register::A0, !0);
                    }
                    66 => {
                        //writev()
                    }
                    _ => {
                        panic!("unhandled syscall {}\n", num)
                    }
                }
                let pc = emu.reg(Register::Pc);
                emu.set_reg(Register::Pc, pc.wrapping_add(4));
            }
        }
    }
}

//! A 64-bit RISC-V RV64i interpreter

use crate::mmu::{Mmu, Perm, VirtAddr, PERM_EXEC};

/// Reasons why the VM exited
#[derive(Clone, Copy, Debug)]
pub enum VmExit {
    /// The address requested was not in bounds of the guest memory space
    AddressMiss(VirtAddr, usize),

    /// A read or write memory request overflowed the address size
    AddressIntegerOverflow,

    /// The VM exited cleanly as requested by the VM
    Exit,

    /// A read of `VirtAddr` failed due to missing permissions 
    ReadFault(VirtAddr),

    /// The VM exited due to a syscall instruction
    Syscall,

    /// An integer overflow occured during a syscall due to bad supplied arguments by the program
    SyscallIntegerOverflow,

    /// A write to `VirtAddr` failed due to missing permissions 
    WriteFault(VirtAddr),
}

/// All the state of the emulated system
pub struct Emulator {
    /// Memory for the emulator
    pub memory: Mmu,

    /// All RV64i registers
    registers: [u64; 33],
}

impl Emulator {
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
            registers: [0; 33],
        }
    }

    /// Fork an emulator into a new emulator which will diff from the original
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
            registers: self.registers.clone(),
        }
    }

    /// Reset the state of 'self' to 'other' assuming that 'self' is forked off
    /// of 'other'. If it is not forked off 'other', the results are invalid
    pub fn reset(&mut self, other: &Self) {
        // Reset memory state
        self.memory.reset(&other.memory);

        // Reset register state
        self.registers = other.registers;
    }

    /// Get a register from the guest
    pub fn reg(&self, register: Register) -> u64 {
        if register != Register::Zero {
            self.registers[register as usize]
        } else {
            0
        }
    }

    /// Set a register in the guest
    pub fn set_reg(&mut self, register: Register, value: u64) {
        if register != Register::Zero {
            self.registers[register as usize] = value;
        }
    }

    pub fn run(&mut self, instrs_execed: &mut u64) -> Result<(), VmExit> {
        // Track number of instructions executed
        'next_inst: loop {
            // Get the current program counter
            let pc = self.reg(Register::Pc);
            let inst: u32 = self
                .memory
                .read_perms(VirtAddr(pc as usize), Perm(PERM_EXEC))?;

            // Update the instructions executed
            *instrs_execed += 1;

            // Extract opcode from instruction (Bits 0-6)
            let opcode = inst & 0b1111111;

            // Written from the top down more or less based on the docs
            // https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf
            match opcode {
                0b0110111 => {
                    // LUI (Load upper immediate)
                    let inst = UType::from(inst);
                    self.set_reg(inst.rd, inst.imm as i64 as u64);
                }
                0b0010111 => {
                    // AUIPC (Add upper immediate PC)
                    let inst = UType::from(inst);
                    self.set_reg(inst.rd,
                                 (inst.imm as i64 as u64).wrapping_add(pc));
                }
                0b1101111 => {
                    // JAL (Jump and Link)
                    let inst = JType::from(inst);
                    self.set_reg(inst.rd, pc.wrapping_add(4));
                    self.set_reg(Register::Pc,
                                 pc.wrapping_add(inst.imm as i64 as u64));
                    continue 'next_inst;
                }
                0b1100111 => {
                    let inst = IType::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // JALR (Jump and Link Register)
                            let target = self.reg(inst.rs1)
                                .wrapping_add(inst.imm as i64 as u64);
                            self.set_reg(inst.rd, pc.wrapping_add(4));
                            self.set_reg(Register::Pc, target);
                            continue 'next_inst;
                        }
                        _ => unimplemented!("unexpected 0b1100111"),
                    }
                }
                0b1100011 => {
                    // We know it's a BType
                    let inst = BType::from(inst);

                    let rs1 = self.reg(inst.rs1);
                    let rs2 = self.reg(inst.rs2);
                    match inst.funct3 {
                        0b000 => {
                            // BEQ (Branch Equal)
                            if rs1 == rs2 {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b001 => {
                            // BNE (Branch Not Equal)
                            if rs1 != rs2 {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b100 => {
                            // BLT (Branch if less than)
                            if (rs1 as i64) < (rs2 as i64) {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b101 => {
                            // BGE (Branch if greater than or equal to)
                            if (rs1 as i64) >= (rs2 as i64) {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b110 => {
                            // BLTU (Branch if less than unsigned)
                            if (rs1 as u64) < (rs2 as u64) {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b111 => {
                            // BGEU (Branch if greater than or
                            // equal to unsigned)
                            if (rs1 as u64) >= (rs2 as u64) {
                                self.set_reg(Register::Pc,
                                             pc.wrapping_add(
                                                 inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        _ => unimplemented!("unexpected 0b1100111"),
                    }
                }
                0b0000011 => {
                    // We know it's an IType
                    let inst = IType::from(inst);

                    let addr =
                        VirtAddr(self.reg(inst.rs1)
                                 .wrapping_add(
                                     inst.imm as i64 as u64) as usize);

                    match inst.funct3 {
                        0b000 => {
                            // LB (Load Byte)
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         i8::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b001 => {
                            // LH (Load Half word)
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         i16::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b010 => {
                            // LW (Load Word)
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         i32::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b011 => {
                            // LD (Load double word)
                            let mut tmp = [0u8; 8];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         i64::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b100 => {
                            // LBU (Load byte unsigned)
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         u8::from_le_bytes(tmp) as u64);
                        }
                        0b101 => {
                            // LHU (Load half-word unsigned)
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         u16::from_le_bytes(tmp) as u64);
                        }
                        0b110 => {
                            // LWU (Load word unsigned)
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd,
                                         u32::from_le_bytes(tmp) as u64);
                        }
                        _ => unimplemented!("unexpected 0b0000011"),
                    }
                }
                0b0100011 => {
                    // SType
                    let inst = SType::from(inst);
                    let addr =
                        VirtAddr(self.reg(inst.rs1).
                                 wrapping_add(inst.imm as i64 as u64) as usize);

                    match inst.funct3 {
                        0b000 => {
                            // SB (Store byte)
                            let val = self.reg(inst.rs2) as u8;
                            self.memory.write(addr, val)?;
                        }
                        0b001 => {
                            // SH (Store half-word)
                            let val = self.reg(inst.rs2) as u16;
                            self.memory.write(addr, val)?;
                        }
                        0b010 => {
                            // SW (Store word)
                            let val = self.reg(inst.rs2) as u32;
                            self.memory.write(addr, val)?;
                        }
                        0b011 => {
                            // SD (Store double word)
                            let val = self.reg(inst.rs2) as u64;
                            self.memory.write(addr, val)?;
                        }
                        _ => unimplemented!("unexpected 0b0100011"),
                    }
                }
                0b0010011 => {
                    // IType
                    let inst = IType::from(inst);
                    let rs1 = self.reg(inst.rs1);
                    let imm = inst.imm as i64 as u64;

                    match inst.funct3 {
                        0b000 => {
                            // ADDI
                            self.set_reg(inst.rd, rs1.wrapping_add(imm));
                        }
                        0b010 => {
                            // SLTI
                            if (rs1 as i64) < (imm as i64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        0b011 => {
                            // SLTIU
                            if (rs1 as u64) < (imm as u64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        0b100 => {
                            // XORI
                            self.set_reg(inst.rd, rs1 ^ imm);
                        }
                        0b110 => {
                            // ORI
                            self.set_reg(inst.rd, rs1 | imm);
                        }
                        0b111 => {
                            // ANDI
                            self.set_reg(inst.rd, rs1 & imm);
                        }
                        0b001 => {
                            let mode = (inst.imm >> 6) & 0b111111;

                            match mode {
                                0b000000 => {
                                    // SLLI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd, rs1 << shamt);
                                }
                                _ => unreachable!(),
                            }
                        }
                        0b101 => {
                            let mode = (inst.imm >> 6) & 0b111111;

                            match mode {
                                0b000000 => {
                                    // SRLI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd, rs1 >> shamt);
                                }
                                0b010000 => {
                                    // SRAI
                                    let shamt = inst.imm & 0b111111;
                                    self.set_reg(inst.rd,
                                                 ((rs1 as i64) >> shamt) as u64);
                                }
                                _ => unimplemented!("unexpected 0b101"),
                            }
                        }
                        _ => unimplemented!("unexpected 0b0010011"),
                    }
                }
                0b0110011 => {
                    // RType
                    let inst = RType::from(inst);

                    let rs1 = self.reg(inst.rs1);
                    let rs2 = self.reg(inst.rs2);

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADD
                            self.set_reg(inst.rd, rs1.wrapping_add(rs2));
                        }
                        (0b0100000, 0b000) => {
                            // SUB
                            self.set_reg(inst.rd, rs1.wrapping_sub(rs2));
                        }
                        (0b0000000, 0b001) => {
                            // SLL (Shift left logical)
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd, rs1 << shamt);
                        }
                        (0b0000000, 0b010) => {
                            // SLT (Set less than)
                            if (rs1 as i64) < (rs2 as i64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        (0b0000000, 0b011) => {
                            // SLTU (Set less than unsigned)
                            if (rs1 as u64) < (rs2 as u64) {
                                self.set_reg(inst.rd, 1);
                            } else {
                                self.set_reg(inst.rd, 0);
                            }
                        }
                        (0b0000000, 0b100) => {
                            // XOR
                            self.set_reg(inst.rd, rs1 ^ rs2);
                        }
                        (0b0000000, 0b101) => {
                            // SRL (Shift right logical)
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd, rs1 >> shamt);
                        }
                        (0b0100000, 0b101) => {
                            // SRA
                            let shamt = rs2 & 0b111111;
                            self.set_reg(inst.rd,
                                         ((rs1 as i64) >> shamt) as u64);
                        }
                        (0b0000000, 0b110) => {
                            // OR
                            self.set_reg(inst.rd, rs1 | rs2);
                        }
                        (0b0000000, 0b111) => {
                            // AND
                            self.set_reg(inst.rd, rs1 & rs2);
                        }
                        _ => unimplemented!("unexpected 0b0110011"),
                    }
                }
                0b0001111 => {
                    let inst = IType::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // FENCE
                        }
                        _ => unreachable!(),
                    }
                }
                0b1110011 => {
                    if inst == 0b00000000000000000000000001110011 {
                        // ECALL
                        return Err(VmExit::Syscall);
                    } else if inst == 0b00000000000100000000000001110011 {
                        // EBREAK
                        panic!("SYSCALL")
                    } else {
                        unreachable!();
                    }
                }
                0b0011011 => {
                    // IType
                    let inst = IType::from(inst);
                    let rs1 = self.reg(inst.rs1) as u32;
                    let imm = inst.imm as u32;

                    match inst.funct3 {
                        0b000 => {
                            // ADDIW
                            self.set_reg(inst.rd,
                                         rs1
                                         .wrapping_add(imm) as i32 as i64 as u64);
                        }
                        0b001 => {
                            let mode = (inst.imm >> 5) & 0b1111111;
                            match mode {
                                0b0000000 => {
                                    // SLLIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd,
                                                 (rs1 << shamt) as i32 as i64 as u64);
                                }
                                _ => unreachable!(),
                            }
                        }
                        0b101 => {
                            let mode = (inst.imm >> 5) & 0b1111111;

                            match mode {
                                0b000000 => {
                                    // SRLIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd,
                                                 (rs1 >> shamt) as i32 as i64 as u64);
                                }
                                0b010000 => {
                                    // SRAIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd,
                                                 ((rs1 as i32) >> shamt) as i64 as u64);
                                }
                                _ => unimplemented!("unexpected 0b101"),
                            }
                        }
                        _ => unimplemented!("unexpected 0b0010011"),
                    }
                }
                0b0111011 => {
                    // RType
                    let inst = RType::from(inst);

                    let rs1 = self.reg(inst.rs1) as u32;
                    let rs2 = self.reg(inst.rs2) as u32;

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADDW
                            self.set_reg(inst.rd, rs1.wrapping_add(rs2) as i32 as i64 as u64);
                        }
                        (0b0100000, 0b000) => {
                            // SUBW
                            self.set_reg(inst.rd, rs1.wrapping_sub(rs2) as i32 as i64 as u64);
                        }
                        (0b0000000, 0b001) => {
                            // SLLW (Shift left logical)
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                        }
                        (0b0000000, 0b101) => {
                            // SRLW
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                        }
                        (0b0100000, 0b101) => {
                            // SRAW
                            let shamt = rs2 & 0b11111;
                            self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                        }
                        _ => unimplemented!("unexpected 0b0110011"),
                    }
                }
                _ => unimplemented!("Unhandled opcode: {:#09b}\n", opcode),
            }

            // Update the pc to the next instruction
            self.set_reg(Register::Pc, pc.wrapping_add(4));
        }
    }
}

#[derive(Debug)]
struct BType {
    imm: i32,
    rs1: Register,
    rs2: Register,
    funct3: u32,
}

impl From<u32> for BType {
    fn from(inst: u32) -> Self {
        let imm12 = ((inst as i32) >> 31) & 1;
        let imm105 = ((inst as i32) >> 25) & 0b111111;
        let imm41 = ((inst as i32) >> 8) & 0b1111;
        let imm11 = ((inst as i32) >> 7) & 1;

        let imm = imm12 << 12 | imm11 << 11 | imm105 << 5 | imm41 << 1;
        let imm = ((imm as i32) << 19) >> 19;

        let rs1: Register = Register::from((inst >> 15) & 0b11111);

        let rs2: Register = Register::from((inst >> 20) & 0b11111);

        let funct3: u32 = (inst >> 12) & 0b111;

        BType {
            imm,
            rs1,
            rs2,
            funct3,
        }
    }
}

#[derive(Debug)]
struct IType {
    imm: i32,
    rs1: Register,
    funct3: u32,
    rd: Register,
}

impl From<u32> for IType {
    fn from(inst: u32) -> Self {
        let imm = (inst as i32) >> 20;

        let rs1: Register = Register::from((inst >> 15) & 0b11111);

        let funct3: u32 = (inst >> 12) & 0b111;

        let rd = Register::from((inst >> 7) & 0b11111);

        IType {
            imm,
            rs1,
            funct3,
            rd,
        }
    }
}

#[derive(Debug)]
struct JType {
    imm: i32,
    rd: Register,
}

impl From<u32> for JType {
    fn from(inst: u32) -> Self {
        let imm20 = (inst >> 31) & 1;
        let imm101 = (inst >> 21) & 0b1111111111;
        let imm11 = (inst >> 20) & 1;
        let imm1912 = (inst >> 12) & 0b11111111;
        let imm = imm20 << 20 | imm1912 << 12 | imm11 << 11 | imm101 << 1;
        let imm = ((imm as i32) << 11) >> 11;

        JType {
            imm,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

#[derive(Debug)]
struct RType {
    rd: Register,
    rs1: Register,
    rs2: Register,
    funct3: u32,
    funct7: u32,
}

impl From<u32> for RType {
    fn from(inst: u32) -> Self {
        let rd = Register::from((inst >> 7) & 0b11111);

        let rs1: Register = Register::from((inst >> 15) & 0b11111);
        let rs2: Register = Register::from((inst >> 20) & 0b11111);

        let funct3: u32 = (inst >> 12) & 0b111;
        let funct7: u32 = (inst >> 25) & 0b1111111;

        RType {
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
        }
    }
}

#[derive(Debug)]
struct SType {
    imm: i32,
    rs1: Register,
    rs2: Register,
    funct3: u32,
}

impl From<u32> for SType {
    fn from(inst: u32) -> Self {
        let imm40 = (inst >> 7) & 0b11111;
        let imm115 = (inst >> 25) & 0b1111111;
        let imm = imm115 << 5 | imm40;
        let imm = ((imm as i32) << 20) >> 20;

        let rs1: Register = Register::from((inst >> 15) & 0b11111);
        let rs2: Register = Register::from((inst >> 20) & 0b11111);

        let funct3: u32 = (inst >> 12) & 0b111;

        SType {
            imm,
            rs1,
            rs2,
            funct3,
        }
    }
}

#[derive(Debug)]
struct UType {
    imm: i32,
    rd: Register,
}

impl From<u32> for UType {
    fn from(inst: u32) -> Self {
        UType {
            imm: (inst & !0xfff) as i32,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

/// 64b-t RISC-V registers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Register {
    Zero = 0,
    Ra,
    Sp,
    Gp,
    Tp,
    T0,
    T1,
    T2,
    S0,
    S1,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    Pc,
}

impl From<u32> for Register {
    fn from(val: u32) -> Self {
        assert!(val < 32);
        unsafe { core::ptr::read_unaligned(&(val as usize) as *const usize as *const Register) }
    }
}

use std::path::Path;

const PERM_READ: u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC: u8 = 1 << 2;
const PERM_RAW: u8 = 1 << 3;

pub unsafe trait Primitive: Default + Clone + Copy {}
unsafe impl Primitive for u8 {}
unsafe impl Primitive for u16 {}
unsafe impl Primitive for u32 {}
unsafe impl Primitive for u64 {}
unsafe impl Primitive for u128 {}
unsafe impl Primitive for usize {}

unsafe impl Primitive for i8 {}
unsafe impl Primitive for i16 {}
unsafe impl Primitive for i32 {}
unsafe impl Primitive for i64 {}
unsafe impl Primitive for i128 {}
unsafe impl Primitive for isize {}

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the smaller, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
const DIRTY_BLOCK_SIZE: usize = 4096;

/// A permissions byte which corresponds to a memory byte and defines the
/// permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Perm(pub u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub usize);

/// An isolated memory space
pub struct Mmu {
    /// Block of memory for this address space
    /// Offset 0 corresponds to address 0 in the guest address space
    memory: Vec<u8>,

    /// Holds the permission bytes for the corresponding byte in memory
    permissions: Vec<Perm>,

    /// Current base address of the next allocation
    cur_alc: VirtAddr,

    /// Tracks blocks indicies in 'memory' which are dirty
    dirty: Vec<usize>,

    /// Tracks which parts of memory have been dirtied
    dirty_bitmap: Vec<u64>,
}

impl Mmu {
    /// Create a new memory space which can hold 'size' bytes
    pub fn new(size: usize) -> Self {
        Mmu {
            memory: vec![0; size],
            permissions: vec![Perm(0); size],
            cur_alc: VirtAddr(0x10000),
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
        }
    }

    /// Fork from an existing MMU
    fn fork(&self) -> Self {
        let size = self.memory.len();
        Mmu {
            memory: self.memory.clone(),
            permissions: self.permissions.clone(),
            cur_alc: self.cur_alc.clone(),
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
        }
    }

    /// Restores memory back to the original state (eg. restores all dirty
    /// blocks to the state of 'other')
    fn reset(&mut self, other: &Mmu) {
        for &block in &self.dirty {
            // Get the start and end addresses of the dirtied memory
            let start = block * DIRTY_BLOCK_SIZE;
            let end = (block + 1) * DIRTY_BLOCK_SIZE;

            // Zero the bitmap. This hits wide, but it's fine, we have to do
            // a 64-bit write anyways, no reason to compute the bit index
            self.dirty_bitmap[block / 64] = 0;

            // Restore memory state
            self.memory[start..end].copy_from_slice(&other.memory[start..end]);

            // Restore permissions
            self.permissions[start..end].copy_from_slice(&other.permissions[start..end]);
        }

        // Clear the dirty list
        self.dirty.clear();
    }

    /// Allocate a region of memory as RW in the address space
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        // 16-byte align the allocation
        let _align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Cannot allocate
        if base.0 >= self.memory.len() {
            return None;
        }

        // Update the allocation size
        self.cur_alc = VirtAddr(self.cur_alc.0.checked_add(size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        // Mark the memory as uninitialized and writable
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        Some(base)
    }

    /// Apply permissions to a region of memory
    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, perm: Perm) -> Option<()> {
        // Apply permissions
        self.permissions
            .get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = perm);

        Some(())
    }

    /// Write the bytes from 'buf' into 'addr'
    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Option<()> {
        let perms = self
            .permissions
            .get_mut(addr.0..addr.0.checked_add(buf.len())?)?;

        let mut has_raw = false;

        // Check permissions
        if !perms.iter().all(|x| {
            has_raw |= (x.0 & PERM_RAW) != 0;
            (x.0 & PERM_WRITE) != 0
        }) {
            return None;
        }

        self.memory
            .get_mut(addr.0..addr.0.checked_add(buf.len())?)?
            .copy_from_slice(buf);

        // Compute dirty bit blocks
        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end = (addr.0 + buf.len()) / DIRTY_BLOCK_SIZE;
        for block in block_start..=block_end {
            // Determine the bitmap position of the dirty block
            let idx = block_start / 64;
            let bit = block_start % 64;
            // Check if block is not dirty
            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                // Block is not dirty, add it to the dirty list
                self.dirty.push(block);

                // Update the dirty bitmap
                self.dirty_bitmap[idx] |= 1 << bit;
            }
        }

        // Update RaW bits
        if has_raw {
            perms.iter_mut().for_each(|x| {
                if (x.0 & PERM_RAW) != 0 {
                    *x = Perm(x.0 | PERM_READ);
                }
            });
        }

        Some(())
    }

    /// Read the memory at 'addr' into 'buf'
    /// This function checks to see if all bits in 'exp_perms' are set in the
    /// permission bytes. If this is zero, we ignore permissions entirely
    pub fn read_into_perms(&self, addr: VirtAddr, buf: &mut [u8], exp_perms: Perm) -> Option<()> {
        let perms = self
            .permissions
            .get(addr.0..addr.0.checked_add(buf.len())?)?;

        // Check permissions
        if exp_perms.0 != 0 && !perms.iter().all(|x| (x.0 & exp_perms.0) == exp_perms.0) {
            return None;
        }

        buf.copy_from_slice(self.memory.get(addr.0..addr.0.checked_add(buf.len())?)?);

        Some(())
    }

    /// Read the memory at 'addr' into 'buf'
    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Option<()> {
        self.read_into_perms(addr, buf, Perm(PERM_READ))
    }

    /// Read a type 'T' at 'addr' expecting 'perms'
    pub fn read<T: Primitive>(&mut self, addr: VirtAddr) -> Option<T> {
        self.read_perms(addr, Perm(PERM_READ))
    }

    /// Read a type 'T' at 'addr' expecting 'perms'
    pub fn read_perms<T: Primitive>(&mut self, addr: VirtAddr, perms: Perm) -> Option<T> {
        let mut tmp = [0u8; 16];
        self.read_into_perms(addr, &mut tmp[..core::mem::size_of::<T>()], perms)?;
        Some(unsafe { core::ptr::read_unaligned(tmp.as_ptr() as *const T) })
    }

    /// Write a 'val' to 'addr'
    pub fn write<T: Primitive>(&mut self, addr: VirtAddr, val: T) -> Option<()> {
        let tmp = unsafe {
            core::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.write_from(addr, tmp)
    }
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

    pub fn run(&mut self) -> Option<()> {
        'next_inst: loop {
            // Get the current program counter
            let pc = self.reg(Register::Pc);
            let inst: u32 = self
                .memory
                .read_perms(VirtAddr(pc as usize), Perm(PERM_EXEC))?;

            // Extract opcode from instruction (Bits 0-6)
            let opcode = inst & 0b1111111;
            print!("PC: {:#x} | opcode: {:b}\n", pc, opcode);

            match opcode {
                0b0110111 => {
                    // LUI (Load upper immediate)
                    let inst = UType::from(inst);
                    self.set_reg(inst.rd, inst.imm as i64 as u64);
                }
                0b0010111 => {
                    // AUIPC (Add upper immediate PC)
                    let inst = UType::from(inst);
                    self.set_reg(inst.rd, (inst.imm as i64 as u64).wrapping_add(pc));
                }
                0b1101111 => {
                    // JAL (Jump and Link)
                    let inst = JType::from(inst);
                    self.set_reg(inst.rd, pc.wrapping_add(4));
                    self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                    continue 'next_inst;
                }
                0b1100111 => {
                    let inst = IType::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // JALR (Jump and Link Register)
                            let target = self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64);
                            self.set_reg(inst.rd, pc.wrapping_add(4));
                            print!("Target: {:#x?}\n", target);
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
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b001 => {
                            // BNE (Branch Not Equal)
                            if rs1 != rs2 {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b100 => {
                            // BLT (Branch if less than)
                            if (rs1 as i64) < (rs2 as i64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b101 => {
                            // BGE (Branch if greater than or equal to)
                            if (rs1 as i64) >= (rs2 as i64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b110 => {
                            // BLTU (Branch if less than unsigned)
                            if (rs1 as u64) < (rs2 as u64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                                continue 'next_inst;
                            }
                        }
                        0b111 => {
                            // BGEU (Branch if greater than or equal to unsigned)
                            if (rs1 as u64) >= (rs2 as u64) {
                                self.set_reg(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
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
                        VirtAddr(self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize);

                    match inst.funct3 {
                        0b000 => {
                            // LB (Load Byte)
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i8::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b001 => {
                            // LH (Load Half word)
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i16::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b010 => {
                            // LW (Load Word)
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i32::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b011 => {
                            // LD (Load double word)
                            let mut tmp = [0u8; 8];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, i64::from_le_bytes(tmp) as i64 as u64);
                        }
                        0b100 => {
                            // LBU (Load byte unsigned)
                            let mut tmp = [0u8; 1];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u8::from_le_bytes(tmp) as u64);
                        }
                        0b101 => {
                            // LHU (Load half-word unsigned)
                            let mut tmp = [0u8; 2];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u16::from_le_bytes(tmp) as u64);
                        }
                        0b110 => {
                            // LWU (Load word unsigned)
                            let mut tmp = [0u8; 4];
                            self.memory.read_into(addr, &mut tmp)?;
                            self.set_reg(inst.rd, u32::from_le_bytes(tmp) as u64);
                        }
                        _ => unimplemented!("unexpected 0b0000011"),
                    }
                }
                0b0100011 => {
                    // SType
                    let inst = SType::from(inst);
                    let addr =
                        VirtAddr(self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize);

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
                                    self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
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
                            self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
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
                        panic!("SYSCALL")
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
                            self.set_reg(inst.rd, rs1.wrapping_add(imm) as i32 as i64 as u64);
                        }
                        0b001 => {
                            let mode = (inst.imm >> 5) & 0b1111111;
                            match mode {
                                0b0000000 => {
                                    // SLLIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
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
                                    self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                                }
                                0b010000 => {
                                    // SRAIW
                                    let shamt = inst.imm & 0b11111;
                                    self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
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
        // Some(())
    }

    /// Load a file into the emulators address space using the sections as described
    pub fn load<P: AsRef<Path>>(&mut self, filename: P, sections: &[Section]) -> Option<()> {
        // Read the input file
        let contents = std::fs::read(&filename).ok()?;

        // Go through each section and load it
        for section in sections {
            // Set memory to writable
            self.memory
                .set_permissions(section.virt_addr, section.mem_size, Perm(PERM_WRITE))?;

            // Write in the original file contents
            self.memory.write_from(
                section.virt_addr,
                contents.get(section.file_off..section.file_off.checked_add(section.file_size)?)?,
            )?;

            // Write in any paddings with zeros
            if section.mem_size > section.file_size {
                let padding = vec![0u8; section.mem_size - section.file_size];
                self.memory.write_from(
                    VirtAddr(section.virt_addr.0.checked_add(section.file_size)?),
                    &padding,
                )?;
            }

            // Demote permissions to originals
            self.memory.set_permissions(
                section.virt_addr,
                section.mem_size,
                section.permissions,
            )?;

            // Update the allocator beyond any sections we load
            self.memory.cur_alc = VirtAddr(std::cmp::max(
                self.memory.cur_alc.0,
                (section.virt_addr.0 + section.mem_size + 0xf) & !0xf,
            ));
        }
        Some(())
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

/// Section information for a file
pub struct Section {
    pub file_off: usize,
    pub virt_addr: VirtAddr,
    pub file_size: usize,
    pub mem_size: usize,
    pub permissions: Perm,
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

fn main() {
    let mut emu = Emulator::new(32 * 1024 * 1024);
    emu.load(
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

    push!(0u64); // Auxp
    push!(0u64); // Envp
    push!(0u64); // Argv end
    push!(argv.0); // Argv
    push!(1u64); // Argc

    emu.run().expect("Failed to execute emulator");
}

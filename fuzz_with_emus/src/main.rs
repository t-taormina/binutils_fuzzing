use std::path::Path;

const PERM_READ: u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC: u8 = 1 << 2;
const PERM_RAW: u8 = 1 << 3;

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the smaller, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
const DIRTY_BLOCK_SIZE: usize = 4096;

/// A permissions byte which corresponds to a memory byte and defines the
/// permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Perm(u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VirtAddr(usize);

/// An isolated memory space
struct Mmu {
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
    pub fn fork(&self) -> Self {
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
    pub fn reset(&mut self, other: &Mmu) {
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
}

/// All the state of the emulated system
struct Emulator {
    /// Memory for the emulator
    pub memory: Mmu,
}

impl Emulator {
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
        }
    }

    /// Fork an emulator into a new emulator which will diff from the original
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
        }
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

/// Section information for a file
struct Section {
    file_off: usize,
    virt_addr: VirtAddr,
    file_size: usize,
    mem_size: usize,
    permissions: Perm,
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
                permissions: Perm(PERM_READ | PERM_EXEC),
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

    {
        let mut forked = emu.fork();
        // forked.memory.write_from(tmp, b"AAAA").unwrap();
        // let mut bytes = [0u8; 4];
        // forked.memory.read_into(tmp, &mut bytes).unwrap();
        // print!("Dirtied {:x?}\n", bytes);
        // print!("After reset: {:x?}\n", bytes);
        for _ in 0..100_000_000 {
            let mut tmp = [0u8; 4];
            emu.memory
                .read_into_perms(VirtAddr(0x11190), &mut tmp, Perm(PERM_EXEC))
                .unwrap();
            print!("{:#02x?}\n", tmp);
            forked.memory.reset(&emu.memory);
        }
    }
}

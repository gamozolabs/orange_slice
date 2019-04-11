#![no_std]

extern crate cpu;

pub trait PhysMem {
    fn alloc_page(&mut self) -> Option<*mut u8>;
    fn read_phys(&mut self, addr: *mut u64) -> Result<u64, &'static str>;
    fn write_phys(&mut self, addr: *mut u64, val: u64) -> Result<(), &'static str>;

    /// Check if a virtual address starting at `addr` for `length` is allowed
    /// for use.
    ///
    /// Returns true if you can safely allocate using `addr` and length,
    /// otherwise false
    fn probe_vaddr(&mut self, addr: usize, length: usize) -> bool;
}

/// Bits for raw page tables and page table entries
#[repr(u64)]
pub enum PTBits {
    Present        = (1 <<  0),
    Writable       = (1 <<  1),
    User           = (1 <<  2),
    WriteThrough   = (1 <<  3),
    CacheDisable   = (1 <<  4),
    Accessed       = (1 <<  5),
    Dirty          = (1 <<  6),
    PageSize       = (1 <<  7), /* Only valid for PDPTEs and PDEs */
    Global         = (1 <<  8),
    ExecuteDisable = (1 << 63),
}

/// Valid page mapping sizes
pub enum MapSize {
    Mapping1GiB,
    Mapping2MiB,
    Mapping4KiB,
}

/// Structure representing a page table
pub struct PageTable<'a, T: 'a + PhysMem> {
    backing: *mut u64,
    physmem: &'a mut T,
}

impl<'a, T: 'a + PhysMem> PageTable<'a, T>
{
    /// Create a new, empty page table
    ///
    /// Unsafe as it is up to the caller to make sure the alloc_page() function
    /// actually correctly allocates pages.
    pub unsafe fn new(physmem: &'a mut T) -> PageTable<'a, T>
    {
        let backing = physmem.alloc_page().unwrap();
        core::ptr::write_bytes(backing, 0, 4096);

        PageTable {
            physmem,
            backing: backing as *mut u64,
        }
    }

    unsafe fn alloc_zeroed_page(&mut self) -> *mut u64
    {
        let ret = self.physmem.alloc_page().unwrap();
        core::ptr::write_bytes(ret, 0, 4096);
        ret as *mut u64
    }

    pub unsafe fn from_existing(existing: *mut u64, physmem: &'a mut T) ->
        PageTable<'a, T>
    {
        PageTable {
            physmem,
            backing: existing,
        }
    }

    /// Get a pointer to the root page table for this page table. This value
    /// is what would be put in cr3.
    pub fn get_backing(&self) -> *mut u64
    {
        self.backing
    }

    /// Create a mapping at `vaddr` in this page table containing the raw
    /// entry `entry`. This can be used to map large pages by using `mapsize`
    pub fn map_page_raw(&mut self, vaddr: u64, entry: u64,
                        mapsize: MapSize, allow_remap: bool) ->
        Result<(), &'static str>
    {
        unsafe {
            /* Check for address to be canon. Technically this does not matter
             * as we don't operate on the top bits, but there should be no
             * instance where get a non-canon address for mapping, so alert
             * the user.
             */
            assert!(vaddr == cpu::canonicalize_address(vaddr),
                "Address is not canonical");

            /* Grab the page table backing */
            let mut cur = self.backing;

            /* All mappings must be at least 4k aligned */
            assert!((vaddr & 0xfff) == 0, "Mapping vaddr not 4k aligned");

            /* Validate that 1GiB and 2MiB mappings have the PS bit set */
            match mapsize {
                MapSize::Mapping1GiB | MapSize::Mapping2MiB =>
                    assert!((entry & PTBits::PageSize as u64) != 0,
                        "Attempted to map a 1 GiB or 2 MiB page without PS"),
                _ => {},
            }

            /* Calculate the components for each level of the page table from
             * the vaddr.
             */
            let cr_offsets: [u64; 4] = [
                ((vaddr >> 39) & 0x1ff),
                ((vaddr >> 30) & 0x1ff),
                ((vaddr >> 21) & 0x1ff),
                ((vaddr >> 12) & 0x1ff),
            ];

            /* Set the maximum table depth, as well as validate alignment for
             * larger pages.
             */
            let max_depth = match mapsize {
                MapSize::Mapping1GiB => {
                    assert!(cr_offsets[2] == 0 && cr_offsets[3] == 0,
                            "1 GiB mapping not 1 GiB aligned");
                    1
                },
                MapSize::Mapping2MiB => {
                    assert!(cr_offsets[3] == 0,
                            "2 MiB mapping not 2 MiB aligned");
                    2
                },
                MapSize::Mapping4KiB => 3,
            };

            /* For each of the top level tables in the page table */
            for cr_depth in 0..max_depth {
                let cur_offset = cr_offsets[cr_depth];

                /* Get the current entry */
                let ent = self.physmem.read_phys(cur.offset(cur_offset as isize))?;

                if ent == 0 {
                    /* If there was no entry present, create a new page table */
                    let new_pt = self.alloc_zeroed_page() as *mut u64;
                    
                    /* Create page table with RWXU permissions */
                    self.physmem.write_phys(cur.offset(cur_offset as isize),
                        new_pt as u64 |
                        PTBits::User     as u64 |
                        PTBits::Writable as u64 |
                        PTBits::Present  as u64)?;

                    cur = new_pt;
                } else {
                    /* Check if this entry is marked present */
                    assert!((ent & PTBits::Present as u64) != 0,
                        "Next level table not present");

                    /* Check if this entry points to a table, or is a mapping
                     * itself. If it's a mapping then we cannot allocate here.
                     */
                    assert!((ent & PTBits::PageSize as u64) == 0,
                        "Large page already allocated at desired mapping");

                    /* If there was an entry present, get the address of the
                     * next level page table.
                     */
                    cur = (ent & 0xFFFFFFFFFF000) as *mut u64;
                }
            }

            /* Read the translation */
            if !allow_remap {
                assert!(self.physmem.read_phys(
                        cur.offset(cr_offsets[max_depth] as isize))? == 0,
                        "Page already mapped");
            }

            /* Commit the new entry */
            self.physmem.write_phys(cur.offset(cr_offsets[max_depth] as isize), entry)?;

            /* If we allowed remapping we must invlpg. If we did not allow
             * remapping we do not have to as the page can only transition from
             * unmapped to mapped and thus will not be in the TLB
             */

            if allow_remap {
                cpu::invlpg(vaddr as usize);
            }
        }

        Ok(())
    }

    /// Translate a virtual address to a physical address using this page table
    /// Optionally dirty pages as we walk performing the translation.
    ///
    /// Returns a tuple of (physical address, page size)
    pub fn virt_to_phys_dirty(&mut self, vaddr: u64, dirty: bool) ->
        Result<Option<(u64, u64)>, &'static str>
    {
        unsafe {
            let mut cur = self.backing;

            /* Non-canonical addresses not translatable */
            assert!(cpu::canonicalize_address(vaddr) == vaddr,
                "Virtual address to virt_to_phys() not canonical");
            
            /* Calculate the components for each level of the page table from
             * the vaddr.
             */
            let cr_offsets: [u64; 4] = [
                ((vaddr >> 39) & 0x1ff), /* 512 GiB */
                ((vaddr >> 30) & 0x1ff), /*   1 GiB */
                ((vaddr >> 21) & 0x1ff), /*   2 MiB */
                ((vaddr >> 12) & 0x1ff), /*   4 KiB */
            ];

            /* For each level in the page table */
            for (depth, cur_offset) in cr_offsets.iter().enumerate() {
                /* Get the page table entry */
                let entry = self.physmem.read_phys(cur.offset(*cur_offset as isize))?;

                /* If the entry is not present return None */
                if (entry & PTBits::Present as u64) == 0 {
                    return Ok(None);
                }

                /* Entry was present, dirty it */
                if dirty {
                    self.physmem.write_phys(cur.offset(*cur_offset as isize),
                        entry | PTBits::Accessed as u64 | PTBits::Dirty as u64)?;
                }

                /* Get the physical address of the next level */
                cur = (entry & 0xFFFFFFFFFF000) as *mut u64;

                /* Check if this is a large page */
                if (entry & PTBits::PageSize as u64) != 0 {
                    match depth {
                        /* PageSize bit set on PML4E (512 GiB page) MBZ */
                        0 => {
                            /* PS bit must be zero on PML4Es */
                            panic!("PageSize bit set on PML4E");
                        },

                        /* PageSize bit set on PDPE (1 GiB page) */
                        1 => {
                            return Ok(Some((cur as u64 + (vaddr & 0x3FFFFFFF),
                                           0x40000000)));
                        },

                        /* PageSize bit set on PDE (2 MiB page) */
                        2 => {
                            return Ok(Some((cur as u64 + (vaddr & 0x1FFFFF),
                                           0x200000)));
                        },
                        
                        /* PageSize bit is the PAT bit at PTE level */
                        _ => {},
                    }
                }
            }

            /* Return out physical address of vaddr and the entry */
            Ok(Some((cur as u64 + (vaddr & 0xfff), 0x1000)))
        }
    }

    /// Translate a virtual address to a physical address
    ///
    /// Return a tuple of (physical address, page size)
    pub fn virt_to_phys(&mut self, vaddr: u64) ->
        Result<Option<(u64, u64)>, &'static str>
    {
        self.virt_to_phys_dirty(vaddr, false)
    }

    /// Checks whether or not the memory range specified by [vaddr..vaddr+size]
    /// is currently free and does not contain any noncanon memory or overflow
    /// conditions.
    ///
    /// This checks assuming the entire range will be mapped in as 4k pages.
    /// This function cannot be used for large pages!
    pub fn can_map_memory(&mut self, vaddr: u64, size: u64) ->
        Result<bool, &'static str>
    {
        /* Zero sized allocations not allowed */
        if size <= 0 {
            return Ok(false);
        }

        /* Non-4k-aligned vaddr not allowed */
        if (vaddr & 0xfff) != 0 {
            return Ok(false);
        }

        /* Check for overflow condition in rounding size up */
        if size.checked_add(0xfff).is_none() {
            return Ok(false);
        }

        /* Round up size to nearest 4k boundry */
        let size = (size + 0xfff) & !0xfff;

        /* Check for vaddr overflow for end address */
        if vaddr.checked_add(size - 1).is_none() {
            return Ok(false);
        }

        /* Go through each page checking that it is free and canon */
        for offset in (0..size).step_by(4096) {
            let vaddr = vaddr + offset;

            /* Check that vaddr is canon */
            if cpu::canonicalize_address(vaddr) != vaddr {
                return Ok(false);
            }

            /* Check if page is already mapped */
            if self.virt_to_phys(vaddr)?.is_some() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Add memory into this page table as RW and fill the pages with zeros.
    pub unsafe fn add_memory_perms(&mut self, vaddr: u64, size: u64,
                                   read: bool, write: bool, exec: bool,
                                   user: bool) -> Result<(), &'static str>
    {
        assert!(read, "Cannot map in non-readable memory");
        assert!(self.can_map_memory(vaddr, size)?,
                "Cannot map memory in add_memory()");

        /* Round up the size to the nearest 4k boundry */
        let size = (size + 0xfff) & !0xfff;

        for offset in (0..size).step_by(4096) {
            /* Allocate a page */
            let page = self.alloc_zeroed_page();

            let mut ptbits = page as u64 | PTBits::Present as u64;
            if !exec { ptbits |= PTBits::ExecuteDisable as u64; }
            if write { ptbits |= PTBits::Writable as u64; }
            if user  { ptbits |= PTBits::User as u64; }

            /* Add page at this offset */
            self.map_page_raw(vaddr + offset, ptbits,
                              MapSize::Mapping4KiB, false)?;
        }

        Ok(())
    }

    /// Add memory into this page table as RW (non-executable) and fill
    /// the pages with zeros.
    pub fn add_memory(&mut self, vaddr: u64, size: u64) ->
        Result<(), &'static str>
    {
        unsafe { self.add_memory_perms(vaddr, size, true, true, false, false) }
    }

    /// Returns a random 4k-aligned virtual address with at least `size` bytes
    /// free
    pub fn rand_addr(&mut self, size: u64) -> Result<u64, &'static str>
    {
        assert!(size > 0, "Attempted to get random addr of 0 size");

        loop {
            /* Generate 4k-aligned random address */
            let vaddr = cpu::canonicalize_address(cpu::rdtsc_rand() & !0xfff);

            /* Check if the given virtual range overlaps with an OS-reserved
             * range. If we cannot use it we try a new address
             */
            if !self.physmem.probe_vaddr(vaddr as usize, size as usize) {
                continue;
            }

            /* Check if this address for size is mappable */
            if self.can_map_memory(vaddr, size)? {
                return Ok(vaddr);
            }
        }
    }

    /// Create an identity map for up to `max_phys` bytes. This value will be
    /// rounded up to the nearest 1 GiB size and must not be zero.
    ///
    /// Since this is an identity map it starts at vaddr 0.
    pub fn add_identity_map(&mut self, max_phys: u64) ->
        Result<(), &'static str>
    {
        /* 0 byte mapping not allowed */
        assert!(max_phys > 0, "Attempted to add identity map of 0 bytes");

        /* Round up to neareast 1GiB */
        let max_phys = (max_phys + 0x3FFFFFFF) & !0x3FFFFFFF;

        for phys in (0..max_phys).step_by(0x40000000) {
            /* TODO: Make identity map non-executable if we can figure out
             *       how to trampoline to 64-bit code in a better way.
             */
            self.map_page_raw(phys, phys |
                              PTBits::PageSize as u64 |
                              //PTBits::ExecuteDisable as u64 |
                              PTBits::Writable as u64 |
                              PTBits::Present  as u64, MapSize::Mapping1GiB,
                              false)?;
        }

        Ok(())
    }

    pub fn unmap_page(&mut self, vaddr: u64) ->
        Result<[Option<u64>; 4], &'static str>
    {
        unsafe {
            let mut cur = self.backing;

            /* Non-canonical addresses not translatable */
            assert!(cpu::canonicalize_address(vaddr) == vaddr,
                "Virtual address to virt_to_phys() not canonical");
            
            /* Calculate the components for each level of the page table from
             * the vaddr.
             */
            let cr_offsets: [isize; 4] = [
                ((vaddr >> 39) & 0x1ff) as isize, /* 512 GiB */
                ((vaddr >> 30) & 0x1ff) as isize, /*   1 GiB */
                ((vaddr >> 21) & 0x1ff) as isize, /*   2 MiB */
                ((vaddr >> 12) & 0x1ff) as isize, /*   4 KiB */
            ];

            let mut free_table: [(bool, u64); 4] = [(false, 0); 4];

            /* For each level in the page table */
            for (depth, &cur_offset) in cr_offsets.iter().enumerate() {
                /* Count the number of non-free page table entries at each
                 * level.
                 */
                let mut counts = 0;
                for page in 0..512 {
                    if self.physmem.read_phys(cur.offset(page))? != 0 {
                        counts += 1;
                    }
                }
                free_table[depth] = (counts == 1, cur as u64);

                /* Get the page table entry */
                let entry = self.physmem.read_phys(cur.offset(cur_offset))?;

                /* If the entry is not present return None */
                if (entry & PTBits::Present as u64) == 0 {
                    return Err("Page not present");
                }

                /* Get the physical address of the next level */
                cur = (entry & 0xFFFFFFFFFF000) as *mut u64;

                /* Check if this is a large page */
                if (entry & PTBits::PageSize as u64) != 0 {
                    match depth {
                        /* PageSize bit set on PML4E (512 GiB page) MBZ */
                        0 => {
                            /* PS bit must be zero on PML4Es */
                            panic!("PageSize bit set on PML4E");
                        },

                        /* PageSize bit set on PDPE (1 GiB page) */
                        1 => {
                            return Err("Cannot unmap 1 GiB pages");
                        },

                        /* PageSize bit set on PDE (2 MiB page) */
                        2 => {
                            return Err("Cannot unmap 2 MiB pages");
                        },
                        
                        /* PageSize bit is the PAT bit at PTE level */
                        _ => {},
                    }
                }
            }

            let mut free_list = [None; 4];

            /* Unlink the page from the page table */
            self.physmem.write_phys(
                (free_table[3].1 as *mut u64).offset(cr_offsets[3]), 0)?;

            for &depth in &[3, 2, 1] {
                if free_table[depth].0 == true {
                    let above = free_table[depth - 1].1 as *mut u64;
                    self.physmem.write_phys(
                        above.offset(cr_offsets[depth - 1]), 0)?;
                    free_list[depth] = Some(free_table[depth].1 as u64);
                } else {
                    break;
                }
            }

            cpu::invlpg(vaddr as usize);

            /* Return out physical address of vaddr and the entry */
            let paddr = cur as u64;
            free_list[0] = Some(paddr);
            Ok(free_list)
        }
    }

    /// Invoke a closure on each page present in this page table. Optionally
    /// if `dirty_only` is true, the closure will only be invoked for dirty
    /// pages.
    ///
    /// XXX: This is marked unsafe until it is correct for tables with large
    ///      pages.
    ///
    /// Dirty pages will be set to clean during the walk if `dirty_only` is
    /// true.
    pub unsafe fn for_each_page<F>(&mut self, dirty_only: bool, mut func: F)
        -> Result<(), &'static str>
        where F: FnMut(u64, u64)
    {
        for pml4e in 0..512u64 {
            let ent = self.backing as *mut u64;
            let tmp = self.physmem.read_phys(ent.offset(pml4e as isize))?;
            if (tmp & PTBits::Present as u64) == 0 { continue; }
            if dirty_only {
                if (tmp & PTBits::Accessed as u64) == 0 {
                    continue;
                }
                self.physmem.write_phys(ent.offset(pml4e as isize),
                    tmp & !(PTBits::Accessed as u64))?;
            }

            let ent = (tmp & 0xFFFFFFFFFF000) as *mut u64;

            for pdpe in 0..512u64 {
                let tmp = self.physmem.read_phys(ent.offset(pdpe as isize))?;
                if (tmp & 1) == 0 { continue; }
                if dirty_only {
                    if (tmp & PTBits::Accessed as u64) == 0 {
                        continue;
                    }
                    self.physmem.write_phys(ent.offset(pdpe as isize),
                                     tmp & !(PTBits::Accessed as u64))?;
                }
                let ent = (tmp & 0xFFFFFFFFFF000) as *mut u64;

                for pde in 0..512u64 {
                    let tmp = self.physmem.read_phys(ent.offset(pde as isize))?;
                    if (tmp & 1) == 0 { continue; }
                    if dirty_only {
                        if (tmp & PTBits::Accessed as u64) == 0 {
                            continue;
                        }
                        self.physmem.write_phys(ent.offset(pde as isize),
                                         tmp & !(PTBits::Accessed as u64))?;
                    }
                    let ent = (tmp & 0xFFFFFFFFFF000) as *mut u64;

                    for pte in 0..512u64 {
                        let tmp = self.physmem.read_phys(ent.offset(pte as isize))?;
                        if (tmp & 1) == 0 { continue; }
                        if dirty_only {
                            if (tmp & PTBits::Dirty as u64) == 0 {
                                continue;
                            }
                            self.physmem.write_phys(ent.offset(pte as isize),
                                tmp & !(PTBits::Dirty as u64))?;
                        }

                        let vaddr = (pml4e << 39) | (pdpe << 30) |
                            (pde << 21) | (pte << 12);
                        let paddr = tmp & 0xFFFFFFFFFF000;

                        func(vaddr as u64, paddr);
                    }
                }
            }
        }

        Ok(())
    }
}


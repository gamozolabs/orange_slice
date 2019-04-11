use core;

use realmode;
use rangeset::{Range, RangeSet};
use core::alloc::{GlobalAlloc, Layout};

/// Global containing the contents of the E820 table
///
/// First value of the tuple is a bool indicating whether allocations are
/// allowed. This is set to false once the MM table has been cloned to pass
/// to the kernel, disabling allocations.
///
/// Second value indicates if the MM subsystem has been initialized.
///
/// Third value is the E820 table in a RangeSet
static mut MM_TABLE: (bool, bool, RangeSet) = (false, false, RangeSet::new());

/// Packed structure describing E820 entries
#[repr(C, packed)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct E820Entry {
    base: u64,
    size: u64,
    typ:  u32,
}

/// Clone the MM table, further disabling allocations
pub fn clone_mm_table() -> RangeSet
{
    unsafe {
        /* Make sure MM is initialized and allocations are enabled */
        assert!(MM_TABLE.1, "MM subsystem has not been initialized");
        assert!(MM_TABLE.0, "MM table has already been cloned");

        /* Disable allocations */
        MM_TABLE.0 = false;

        /* Return copy of MM table */
        MM_TABLE.2.clone()
    }
}

pub unsafe fn remove_range(addr: u64, size: u64)
{
    let rs = &mut MM_TABLE.2;
    assert!(size > 0, "Invalid size for remove_range()");
    rs.remove(Range { start: addr, end: addr.checked_add(size).unwrap() - 1 });
}

/// Initialize the memory managment state. This requests the e820 table from
/// the BIOS and checks for overlapping/double mapped ranges.
pub unsafe fn init()
{
    let rs = &mut MM_TABLE.2;

    /* Loop through the E820 twice. The first time we loop we want to
     * accumulate free sections into the RangeSet. The second loop we want
     * to remove nonfree sections.
     */
    for &add_entries in &[true, false] {
        /* Continuation code, starts off at 0. BIOS implementation specific
         * after first call to e820.
         */
        let mut cont = 0;

        /* Get the E820 table from the BIOS, entry by entry */
        loop {
            let mut ent = E820Entry { base: 0, size: 0, typ: 0 };

            /* Set up the register state for the BIOS call */
            let mut regs = realmode::RegisterState {
                eax: 0xe820,     /* Function 0xE820       */
                ecx: 20,         /* Entry size (in bytes) */
                edx: 0x534d4150, /* Magic number 'PAMS'   */
                ebx: cont,       /* Continuation number   */
                edi: &mut ent as *const _ as u32, /* Pointer to buffer */
                ..Default::default()
            };

            /* Invoke BIOS int 0x15, function 0xE820 to get the memory
             * entries
             */
            realmode::invoke_realmode(0x15, &mut regs);

            /* Validate eax contains correct 'SMAP' magic signature */
            assert!(regs.eax == 0x534d4150,
                    "E820 did not report correct magic");

            /* Validate size of E820 entry is >= what we expect */
            assert!(regs.ecx as usize >= core::mem::size_of_val(&ent),
                    "E820 entry structure was too small");

            assert!(ent.size > 0, "E820 entry of zero size");

            /* Safely compute end of memory region */
            let ent_end = match ent.base.checked_add(ent.size - 1) {
                Some(x) => x,
                None    => panic!("E820 entry integer overflow"),
            };

            /* Either insert free regions on the first iteration of the loop
             * or remove used regions in the second iteration.
             */
            if add_entries && ent.typ == 1 {
                rs.insert(Range { start: ent.base, end: ent_end });
            } else if !add_entries && ent.typ != 1 {
                rs.remove(Range { start: ent.base, end: ent_end });
            }

            /* If ebx (continuation number) is zero or CF (error) was set,
             * break out of the loop.
             */
            if regs.ebx == 0 || (regs.efl & 1) == 1 {
                break;
            }

            /* Update continuation */
            cont = regs.ebx;
        }
    }

    /* Remove the first 1MB of memory from allocatable memory. This is to
     * prevent BIOS data structures and our PXE image from being removed.
     */
    rs.remove(Range { start: 0, end: 0xFFFFF });

    /* Mark MM as initialized and allocations enabled */
    MM_TABLE.0 = true;
    MM_TABLE.1 = true;
}

/// Structure representing global allocator
///
/// All state is handled elsewhere so this is empty.
pub struct GlobalAllocator;

unsafe impl GlobalAlloc for GlobalAllocator {
    /// Global allocator. Grabs free memory from E820 and removes it from
    /// the table.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8
    {
        assert!(MM_TABLE.1, "Attempted to allocate with mm uninitialized");
        assert!(MM_TABLE.0, "Attempted to allocate with allocations disabled");

        let rs = &mut MM_TABLE.2;

        /* All the actual work is done in alloc_rangeset() */
        let ret = rs.allocate(layout.size() as u64, layout.align() as u64);
        if ret.is_null() {
            panic!("Allocation failure");
        } else {
            ret as *mut u8
        }
    }

    /// No free implementation.
    ///
    /// We really have no reason to free in the bootloader, so we do not
    /// support a free. We could easily add support if really needed, but
    /// having free panic will prevent us from accidentally allocating data
    /// and passing it to the next stage by pointer, and letting it drop.
    /// Given we don't free anything in the bootloader, anything we pass to
    /// the next stage is always valid.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout)
    {
        panic!("Dealloc attempted\n");
    }
}

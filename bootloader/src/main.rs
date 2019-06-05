#![no_std]
#![no_main]
#![feature(const_fn)]
#![feature(lang_items)]
#![feature(core_intrinsics)]
#![feature(compiler_builtins_lib)]
#![feature(allocator_api)]

/// Custom non-formatting panic macro.
///
/// This overrides the existing panic macro to provide a core::fmt-less panic
/// implementation. This is a lot lighter as it results in no use of core::fmt
/// in the binary. This is a strong requirement for how we can fit this program
/// into the 32KiB PXE requirements.
///
/// Under the hood assert!() uses panic!(), thus we also have assert!()s go
/// through here as well, allowing for idiomatic Rust assert usage.
macro_rules! panic {
    () => ({
        $crate::serial::write("!!! PANIC !!!\n");
        $crate::serial::write("Explicit panic\n");
        $crate::cpu::halt();
    });
    ($msg:expr) => ({
        $crate::serial::write("!!! PANIC !!!\n");
        $crate::serial::write($msg);
        $crate::serial::write_byte(b'\n');
        $crate::cpu::halt();
    });
}

/* External rust-provided crates */
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate bytesafe_derive;

/* Shared crates between bootloader and kernel */
extern crate serial;
extern crate cpu;
extern crate rangeset;
extern crate safecast;
extern crate mmu;

pub mod panic;
pub mod core_reqs;
pub mod realmode;
pub mod mm;
pub mod pxe;
pub mod pe;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::alloc::{Layout, GlobalAlloc};

/// Global allocator
#[global_allocator]
static GLOBAL_ALLOCATOR: mm::GlobalAllocator = mm::GlobalAllocator;

/// Physical memory implementation
///
/// This is used during page table operations
pub struct Pmem {}

impl mmu::PhysMem for Pmem {
    /// Allocate a page
    fn alloc_page(&mut self) -> Option<*mut u8> {
        unsafe {
            let layout = Layout::from_size_align(4096, 4096).unwrap();
            let alloc = GLOBAL_ALLOCATOR.alloc(layout);
            if alloc.is_null() {
                None
            } else {
                Some(alloc as *mut u8)
            }
        }
    }

    /// Read a 64-bit value at the physical address specified
    fn read_phys(&mut self, addr: *mut u64) -> Result<u64, &'static str> {
        unsafe { Ok(core::ptr::read(addr)) }
    }
    
    /// Write a 64-bit value to the physical address specified
    fn write_phys(&mut self, addr: *mut u64, val: u64) ->
            Result<(), &'static str> {
        unsafe { Ok(core::ptr::write(addr, val)) }
    }

    /// This is used to let the MMU know if we reserve memory outside of
    /// the page tables. Since we do not do this at all we always return true
    /// allowing any address not in use in the page tables to be used for
    /// ASLR.
    fn probe_vaddr(&mut self, _addr: usize, _length: usize) -> bool {
        true
    }
}

/// CoreInfo structure to pass into the next stage (kernel). This provides
/// the kernel with critical structures that were constructed in the bootloader
struct CoreInfo {
    entry:           u64,
    stack_base:      u64,
    bootloader_info: cpu::BootloaderStruct,
}

static mut CORE_INFO: Option<Vec<CoreInfo>> = None;
static mut PMEM: Pmem = Pmem {};
static mut PAGE_TABLE: Option<mmu::PageTable<'static, Pmem>> = None;

#[lang = "oom"]
#[no_mangle]
pub extern fn rust_oom(_layout: Layout) -> ! {
    panic!("Out of memory");
}

/// Main entry point for this codebase
///
/// * `soft_reboot_entry` - 32-bit physical address we can branch to at
///   later stages to do a soft reboot of the kernel
/// * `first_boot` - Set if this is the first time the system has booted
#[no_mangle]
pub extern fn entry(soft_reboot_entry: u32, first_boot: bool,
                    kbuf: *mut cpu::KernelBuffer) -> !
{
    static CORE_IDS: AtomicUsize = AtomicUsize::new(0);

    /// Stack size allocated for each core
    const STACK_SIZE: u64 = 1024 * 1024;

    let kbuf = unsafe { &mut *kbuf };

    /* Allocate a unique, sequential core ID for this core */
    let core_id = CORE_IDS.fetch_add(1, Ordering::SeqCst);

    if cpu::is_bsp() {
        /* Initialize the MM subsystem. This is unsafe as this can only be
         * done once.
         */
        unsafe { mm::init(); }

        /* Prevent the kernel buffer from being used as free memory */
        if !first_boot && kbuf.kernel_buffer_size != 0xbaadb00d {
            unsafe {
                mm::remove_range(kbuf.kernel_buffer,
                                 kbuf.kernel_buffer_max_size);
            }
        }

        /* Print our boot banner :) */
        serial::write("=== orange_slice bootloader v2 ===\n");

        /* Validate that the CPU supports the features we use */
        let features = cpu::get_cpu_features();
        assert!(features.bits64);
        assert!(features.xd);
        assert!(features.gbyte_pages);
        assert!(features.sse);
        assert!(features.sse2);
        assert!(features.sse3);
        assert!(features.ssse3);
        assert!(features.sse4_1);
        assert!(features.sse4_2);

        /* Download the kernel */
        let kernel_pe = if first_boot || kbuf.kernel_buffer_size == 0xbaadb00d {
            let mut pe = pxe::download_file("orange_slice.kern");
            kbuf.kernel_buffer = pe.as_mut_ptr() as u64;
            kbuf.kernel_buffer_size = pe.len() as u64;
            kbuf.kernel_buffer_max_size = pe.capacity() as u64;
            pe
        } else {
            unsafe {
                Vec::from_raw_parts(kbuf.kernel_buffer as *mut u8,
                                    kbuf.kernel_buffer_size as usize,
                                    kbuf.kernel_buffer_max_size as usize)
            }
        };

        // Parse the PE file
        let pe_parsed = pe::parse(&kernel_pe);

        // Create a new page table with a 1 TiB identity map
        let mut page_table = unsafe { mmu::PageTable::new(&mut PMEM) };
        page_table.add_identity_map(1024 * 1024 * 1024 * 1024).unwrap();

        unsafe {
            assert!(PAGE_TABLE.is_none(), "Page table already set");
            PAGE_TABLE = Some(page_table);
        }

        let page_table = unsafe { PAGE_TABLE.as_mut().unwrap() };

        // Generate a random address to base the kernel at and load the
        // kernel into the new page table.
        let kernel_base = page_table.rand_addr(pe_parsed.loaded_size())
            .unwrap();
        let kernel_base = 0x1337_0000_0000;
        let entry = pe_parsed.load(page_table, kernel_base);

        for _ in 0..cpu::MAX_CPUS {
            /* Add a 1 MiB stack with random base address */
            let stack_base = page_table.rand_addr(STACK_SIZE).unwrap();
            page_table.add_memory(stack_base, STACK_SIZE).unwrap();

            /* Construct the core infos to be passed to the kernel */
            unsafe {
                if CORE_INFO.is_none() {
                    CORE_INFO = Some(Vec::with_capacity(cpu::MAX_CPUS));
                }
                let ci = CORE_INFO.as_mut().unwrap();

                /* Construct the core info for this CPU */
                ci.push(CoreInfo {
                    entry,
                    stack_base,
                    bootloader_info: cpu::BootloaderStruct {
                        phys_memory:       rangeset::RangeSet::new(),
                        soft_reboot_entry: soft_reboot_entry as u64,
                        kernel_buffer: 
                            kbuf as *mut cpu::KernelBuffer as u64,
                    },
                });
            }
        }

        /* For the BSP, create a copy of the physical memory map to pass
         * to the kernel. Once this operation is performed no more dynamic
         * allocations can occur in the bootloader. They will panic.
         * 
         * This behavior is required such that the bootloader never takes
         * ownership of physical memory that has been given to the kernel as
         * free.
         */
        unsafe {
            CORE_INFO.as_mut().unwrap()[core_id].bootloader_info.phys_memory =
                mm::clone_mm_table();
        }

        /* Prevent all structures from being freed */
        core::mem::forget(pe_parsed);
        core::mem::forget(kernel_pe);
    }

    unsafe {
        /* Get a reference to this core's core info */
        let core_info = &CORE_INFO.as_ref().unwrap()[core_id];

        extern {
            fn enter64(entry: u64, stack: u64, param: u64, cr3: u32) -> !;
        }

        /* Jump into x86_64 kernel! */
        enter64(core_info.entry, core_info.stack_base + STACK_SIZE,
                &core_info.bootloader_info as *const _ as u64,
                PAGE_TABLE.as_ref().unwrap().get_backing() as u32);
    }
}

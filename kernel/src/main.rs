#![no_std]
#![no_main]
#![feature(const_fn)]
#![feature(lang_items)]
#![feature(core_intrinsics)]
#![feature(compiler_builtins_lib)]
#![feature(allocator_api)]
#![feature(asm)]
#![allow(dead_code)]
#![feature(global_asm)]
#![feature(panic_info_message)]

extern crate alloc;

extern crate serial;
extern crate cpu;
extern crate rangeset;
extern crate mmu;

#[macro_use] extern crate bytesafe_derive;

use core::sync::atomic::{AtomicUsize, Ordering};

/// Global allocator
#[global_allocator]
static GLOBAL_ALLOCATOR: mm::GlobalAllocator = mm::GlobalAllocator;

macro_rules! print {
    ( $($arg:tt)* ) => ({
        use core::fmt::Write;
        use core::sync::atomic::{AtomicUsize, Ordering};
        static PRINT_LOCK:     AtomicUsize = AtomicUsize::new(0);
        static PRINT_LOCK_REL: AtomicUsize = AtomicUsize::new(0);

        let ticket = PRINT_LOCK.fetch_add(1, Ordering::SeqCst);
        while ticket != PRINT_LOCK_REL.load(Ordering::SeqCst) {}

        let _ = write!(&mut $crate::Writer, $($arg)*);

        PRINT_LOCK_REL.fetch_add(1, Ordering::SeqCst);
    })
}

/// ACPI code
pub mod acpi;

/// Panic handler
pub mod panic;

/// Core requirements needed for Rust, such as libc memset() and friends
pub mod core_reqs;

/// Bring in the memory manager
pub mod mm;

/// Writer implementation used by the `print!` macro
pub struct Writer;

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial::write(s);
        Ok(())
    }
}

#[lang = "oom"]
#[no_mangle]
pub extern fn rust_oom(_layout: alloc::alloc::Layout) -> ! {
    panic!("Out of memory");
}

/// Main entry point for this codebase
#[no_mangle]
pub extern fn entry(param: u64) -> ! {
    static CORE_ID: AtomicUsize = AtomicUsize::new(0);

    // Convert the bootloader parameter into a reference
    let param = unsafe { &*(param as *const cpu::BootloaderStruct) };

    // Get a unique core identifier for this processor
    let core_id = CORE_ID.fetch_add(1, Ordering::SeqCst);

    if cpu::is_bsp() {
        unsafe {
            acpi::init(&param.phys_memory).expect("Failed to initialize ACPI");
        }
    }

    // Attempt to launch the next processor in the list
    unsafe {
        acpi::launch_ap(core_id + 1);
    }

    use alloc::vec::Vec;
    
    for ii in 0..100000 {
        let mut alc: Vec<u8> = Vec::with_capacity(1024 * 1024);
        for _ in 0..1024*1024 { alc.push(5); }

        if ii % 1000 == 0 {
            print!("ii is {}\n", ii);
        }
    }

    let foo = 0;
    print!("Hello world, paramater is {:p}\n", &foo);
    cpu::halt();
}

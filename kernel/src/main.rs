#![no_std]
#![no_main]
#![feature(const_fn)]
#![feature(lang_items)]
#![feature(core_intrinsics)]
#![feature(compiler_builtins_lib)]
#![feature(alloc)]
#![feature(allocator_api)]
#![feature(asm)]
#![allow(dead_code)]
#![feature(global_asm)]
#![feature(panic_info_message)]

macro_rules! print {
    ( $($arg:tt)* ) => ({
        use core::fmt::Write;
        let _ = write!(&mut $crate::Writer, $($arg)*);
    })
}

extern crate alloc;

extern crate serial;
extern crate cpu;
extern crate rangeset;
extern crate mmu;

/// Panic handler
pub mod panic;

/// Core requirements needed for Rust, such as libc memset() and friends
pub mod core_reqs;

use alloc::alloc::Layout;
use alloc::alloc::GlobalAlloc;

/// Global allocator
#[global_allocator]
pub static mut GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator;

/// Structure representing global allocator
///
/// All state is handled elsewhere so this is empty.
pub struct GlobalAllocator;

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        panic!("ALLOC NOT SUPPORTED");
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        panic!("Dealloc attempted\n");
    }
}

/// Writer implementation used by the `print!` macro
pub struct Writer;

impl core::fmt::Write for Writer
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
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
pub extern fn entry(param: u64) -> !
{
    print!("Hello world, paramater is {:#x}\n", param);
    cpu::halt();
}

use serial;
use cpu;
use core::panic::PanicInfo;

/// Panic implementation
///
/// This currently breaks ABI. This is supposed to be "pub extern fn". By
/// breaking the ABI we let LTO happen, which deletes much code being used
/// to generate formatted parameters for panic. To make this safe we use no
/// parameters passed in here at all.
#[panic_handler]
#[no_mangle]
pub fn panic(_info: &PanicInfo) -> ! {
    serial::write("!!! PANIC !!!\n");
    serial::write("Hit rust_begin_unwind()\n");
    cpu::halt();
}


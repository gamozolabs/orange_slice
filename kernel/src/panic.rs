use cpu;
use core::panic::PanicInfo;

/// Panic implementation
#[panic_handler]
#[no_mangle]
pub fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        print!("!!! PANIC !!! {}:{} ",
            location.file(), location.line(),);
    } else {
        print!("!!! PANIC !!! Panic with no location info ");
    }

    if let Some(&args) = info.message() {
        use core::fmt::write;
        let _ = write(&mut ::Writer, args);
        print!("\n");
    } else {
        print!("No arguments\n");
    }

    cpu::halt();
}

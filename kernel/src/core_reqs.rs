/// libc `memcpy` implementation in rust
///
/// This implementation of `memcpy` is overlap safe, making it technically
/// `memmove`.
///
/// # Parameters
///
/// * `dest` - Pointer to memory to copy to
/// * `src`  - Pointer to memory to copy from
/// * `n`    - Number of bytes to copy
///
#[no_mangle]
pub unsafe extern fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8
{
    memmove(dest, src, n)
}

/// libc `memmove` implementation in rust
///
/// # Parameters
///
/// * `dest` - Pointer to memory to copy to
/// * `src`  - Pointer to memory to copy from
/// * `n`    - Number of bytes to copy
///
#[no_mangle]
pub unsafe extern fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8
{
    if src < dest as *const u8 {
        /* copy backwards */
        let mut ii = n;
        while ii != 0 {
            ii -= 1;
            *dest.offset(ii as isize) = *src.offset(ii as isize);
        }
    } else {
        /* copy forwards */
        let mut ii = 0;
        while ii < n {
            *dest.offset(ii as isize) = *src.offset(ii as isize);
            ii += 1;
        }
    }

    dest
}

/// libc `memset` implementation in rust
///
/// # Parameters
///
/// * `s` - Pointer to memory to set
/// * `c` - Character to set `n` bytes in `s` to
/// * `n` - Number of bytes to set
///
#[no_mangle]
pub unsafe extern fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8
{
    let mut ii = 0;
    while ii < n {
        *s.offset(ii as isize) = c as u8;
        ii += 1;
    }

    s
}

/// libc `memcmp` implementation in rust
///
/// # Parameters
///
/// * `s1` - Pointer to memory to compare with s2
/// * `s2` - Pointer to memory to compare with s1
/// * `n`  - Number of bytes to set
#[no_mangle]
pub unsafe extern fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32
{
    let mut ii = 0;
    while ii < n {
        let a = *s1.offset(ii as isize);
        let b = *s2.offset(ii as isize);
        if a != b {
            return a as i32 - b as i32
        }
        ii += 1;
    }
    
    0
}

/// Fake `__chkstk()` stub. This is just a nop. If we run out of stack we will
/// crash with a page fault, but that'll have to do.
#[no_mangle]
pub unsafe extern fn __chkstk() {}

// Making a fake __CxxFrameHandler3 in Rust causes a panic, this is hacky
// workaround where we declare it as a function that will just crash if it
// gets called.
// We should never hit this so it doesn't matter.
global_asm!(r#"
    .global __CxxFrameHandler3
    __CxxFrameHandler3:
        ud2
"#);

#[no_mangle]
pub unsafe extern fn cos() -> ! { panic!("Unhandled cos"); }

#[no_mangle]
pub unsafe extern fn cosf() -> ! { panic!("Unhandled cosf"); }

#[no_mangle]
pub unsafe extern fn sinf() -> ! { panic!("Unhandled sinf"); }

#[no_mangle]
pub unsafe extern fn sin() -> ! { panic!("Unhandled sin"); }


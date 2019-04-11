#![no_std]

/// Trait specifying that a structure can be safely cast to other ByteSafe
/// structures. This indicates there are no possible invalid encodings with
/// any underlying binary data.
///
/// Trait is unsafe as `Self` must *only* composed of types with no
/// unsafe/invalid binary representations, and has no padding of members.
///
/// Use #[derive(ByteSafe)] on a structure to get this trait safely. The
/// custom derive will validate the structure satisfies all requirements to
/// implement this safely.
///
/// To be extremely strict the only allowed types are: u8, u16, u32, u64,
/// usize, i8, i16, i32, i64, and isize.
///
/// Self must contain no padding as casting padding could make it readable
/// and this is UB.
pub unsafe trait ByteSafe { fn bytesafe() {} }

/* XXX XXX XXX XXX
 * Currently we rely on runtime checks for casting safety. Directly using
 * ByteSafe without calling ByteSafe::bytesafe(self); is UB!!!
 *
 * You should only ever use SafeCast and always cast it, this allows for
 * runtime checks to be run.
 */

/* Raw base types which are plain old data */
unsafe impl ByteSafe for u8    {}
unsafe impl ByteSafe for u16   {}
unsafe impl ByteSafe for u32   {}
unsafe impl ByteSafe for u64   {}
unsafe impl ByteSafe for usize {}
unsafe impl ByteSafe for i8    {}
unsafe impl ByteSafe for i16   {}
unsafe impl ByteSafe for i32   {}
unsafe impl ByteSafe for i64   {}
unsafe impl ByteSafe for isize {}

/* Slices and arrays of ByteSafe types are allowed.
 *
 * While we mark slices as safe, they are *not* allowed inside of structures
 * as they would contain pointers. This is safely protected against in the
 * #[derive(ByteSafe)] code.
 */
unsafe impl<T: ByteSafe> ByteSafe for [T]     {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   0] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   1] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   2] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   3] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   4] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   5] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   6] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   7] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   8] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;   9] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  10] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  11] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  12] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  13] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  14] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  15] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  16] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  17] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  18] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  19] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  20] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  21] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  22] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  23] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  24] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  25] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  26] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  27] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  28] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  29] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  30] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  31] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  32] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  33] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  34] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  35] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  36] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  37] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  38] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  39] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  40] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  41] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  42] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  43] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  44] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  45] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  46] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  47] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  48] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  49] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  50] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  51] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  52] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  53] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  54] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  55] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  56] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  57] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  58] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  59] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  60] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  61] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  62] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  63] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  64] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  65] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  66] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  67] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  68] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  69] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  70] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  71] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  72] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  73] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  74] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  75] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  76] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  77] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  78] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  79] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  80] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  81] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  82] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  83] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  84] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  85] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  86] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  87] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  88] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  89] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  90] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  91] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  92] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  93] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  94] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  95] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  96] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  97] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  98] {}
unsafe impl<T: ByteSafe> ByteSafe for [T;  99] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 100] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 101] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 102] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 103] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 104] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 105] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 106] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 107] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 108] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 109] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 110] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 111] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 112] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 113] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 114] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 115] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 116] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 117] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 118] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 119] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 120] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 121] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 122] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 123] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 124] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 125] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 126] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 127] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 128] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 129] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 130] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 131] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 132] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 133] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 134] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 135] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 136] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 137] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 138] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 139] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 140] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 141] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 142] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 143] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 144] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 145] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 146] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 147] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 148] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 149] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 150] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 151] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 152] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 153] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 154] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 155] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 156] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 157] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 158] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 159] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 160] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 161] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 162] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 163] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 164] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 165] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 166] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 167] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 168] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 169] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 170] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 171] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 172] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 173] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 174] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 175] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 176] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 177] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 178] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 179] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 180] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 181] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 182] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 183] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 184] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 185] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 186] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 187] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 188] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 189] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 190] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 191] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 192] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 193] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 194] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 195] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 196] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 197] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 198] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 199] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 200] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 201] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 202] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 203] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 204] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 205] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 206] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 207] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 208] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 209] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 210] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 211] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 212] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 213] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 214] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 215] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 216] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 217] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 218] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 219] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 220] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 221] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 222] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 223] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 224] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 225] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 226] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 227] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 228] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 229] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 230] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 231] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 232] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 233] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 234] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 235] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 236] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 237] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 238] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 239] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 240] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 241] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 242] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 243] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 244] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 245] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 246] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 247] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 248] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 249] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 250] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 251] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 252] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 253] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 254] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 255] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 256] {}

unsafe impl<T: ByteSafe> ByteSafe for [T;  768] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 2408] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 3928] {}
unsafe impl<T: ByteSafe> ByteSafe for [T; 4096] {}

/* Implement SafeCast trait for all T and [T] where T: ByteSafe */
impl<T: ByteSafe> SafeCast for T   {}
impl<T: ByteSafe> SafeCast for [T] {}

/// SafeCast implementation
///
/// If the type is marked ByteSafe this can be implemented. Using this the
/// type can be cast or copied to other types given the other type implements
/// ByteSafe as well.
pub trait SafeCast: ByteSafe {
    /// Copy the underlying bits from `Self` into `dest`
    ///
    /// This is similar to cast_copy, however it copies into a mutable
    /// reference. This makes it possible to copy into sized types such as
    /// a slice of bytes.
    ///
    /// This function will panic if `Self` is not the same size as `dest`
    fn cast_copy_into<T: ByteSafe + ?Sized>(&self, dest: &mut T)
    {
        <T>::bytesafe();
        <Self>::bytesafe();

        /* Validate source and dest are exactly the same size */
        let dest_sz = core::mem::size_of_val(dest);
        let src_sz  = core::mem::size_of_val(self);
        assert!(dest_sz == src_sz);

        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const _ as *const u8,
                dest as *mut _ as *mut u8,
                src_sz);
        }
    }

    /// Copy the underlying bits from `Self` into a new structure of type `T`
    ///
    /// This creates a new `T` on the stack as uninitialized, calls
    /// `cast_copy_into()` to copy Self into it, and returns the result.
    ///
    /// This function will panic if `Self` is not the same size as T
    fn cast_copy<T: ByteSafe>(&self) -> T
    {
        <T>::bytesafe();
        <Self>::bytesafe();

        /* Uninitialized is safe here as we will fill in all of the bytes */
        let mut ret: T = unsafe { core::mem::uninitialized() };
        self.cast_copy_into(&mut ret);
        ret
    }

    /// Cast `Self` into a slice of `T` spanning the size of `Self`
    ///
    /// This function will directly cast the reference of `Self` into a slice
    /// of `T`, given `Self` is evenly divisible by `T` and alignment matches.
    ///
    /// The resulting slice will map all bytes of `Self`, never will a partial
    /// cast occur.
    fn cast<T: ByteSafe>(&self) -> &[T]
    {
        <T>::bytesafe();
        <Self>::bytesafe();

        /* Verify alignment is fine */
        let src_ptr = self as *const _ as *const u8 as usize;
        assert!(core::mem::align_of::<T>() > 0 && 
                (src_ptr % core::mem::align_of::<T>()) == 0,
                "cast alignment mismatch");

        /* Validate that self is evenly divisible by T */
        let dest_sz = core::mem::size_of::<T>();
        let src_sz  = core::mem::size_of_val(self);
        assert!(dest_sz > 0 && (src_sz % dest_sz) == 0,
            "cast src cannot be evenly divided by T");

        /* Convert self into a slice of T's */
        unsafe {
            core::slice::from_raw_parts(self as *const _ as *const T,
                                       src_sz / dest_sz)
        }
    }

    /// Cast `Self` into a slice of `T` spanning the size of `Self` mutably
    ///
    /// This function will directly cast the reference of `Self` into a slice
    /// of `T`, given `Self` is evenly divisible by `T` and alignment matches.
    ///
    /// The resulting slice will map all bytes of `Self`, never will a partial
    /// cast occur.
    fn cast_mut<T: ByteSafe>(&mut self) -> &mut [T]
    {
        <T>::bytesafe();
        <Self>::bytesafe();

        /* Verify alignment is fine */
        let src_ptr = self as *const _ as *const u8 as usize;
        assert!(core::mem::align_of::<T>() > 0 && 
                (src_ptr % core::mem::align_of::<T>()) == 0,
                "cast_mut alignment mismatch");

        /* Validate that self is evenly divisible by T */
        let dest_sz = core::mem::size_of::<T>();
        let src_sz  = core::mem::size_of_val(self);
        assert!(dest_sz > 0 && (src_sz % dest_sz) == 0,
            "cast_mut src cannot be evenly divided by T");

        /* Convert self into a slice of T's */
        unsafe {
            core::slice::from_raw_parts_mut(self as *mut _ as *mut T,
                                           src_sz / dest_sz)
        }
    }
}


# safecast

An attempt to make a procedural macro to support safe casting in Rust.

## Goals

This library is designed to allow for copying raw underlying data between different types in Rust.
This is helpful for handling things like binary files or network protocols. Using this library you
are able to safely create structures and cast/copy between them.

## Safety

This casting/copying is safe given the following:

- The structure is composed only of types which have no invalid/unsafe underlying binary encodings
    - Currently only `u8`, `u16`, `u32`, `u64`, `usize`, `i8`, `i16`, `i32`, `i64`, `isize` are considered
      to have these properties.
    - Structures may have structures in them which are also packed and contain only the aforementioned
      types.
    - Fixed sized arrays are also allowed.
    - The current implementation is designed to be extra strict. Things like tuples and such would
      be fine in practice but the goal is to keep things simple for now to make it easier to
      verify.
- The structure is packed such that no padding occurs between fields
    - Since the padding between fields contains undefined values this interface could potentially
      expose them if cast to another type where the padding is readable. Thus we disallow use
      of padding in structures. This doesn't matter much anyways as if you're working with binary
      data it's probably packed anyways.

## Interface

`SafeCast::cast_copy_into<T: ByteSafe + ?Sized>(&self, dest: &mut T)`

This routine allows the casting from an existing structure to another type given the other
type also implemented ByteSafe. This method is the one used when `T` is `?Sized`, allowing for
us to cast into things like slices/Vecs. This is the core implementation and is used by
`cast()`.

This method will panic unless both self and T are equal in size (in bytes).

`SafeCast::cast_copy<T: ByteSafe>(&self) -> T`

Creates an uninitialized value of type T, and calls `cast_into` on self
to cast it into T. Returns the new value.

This method will panic unless both self and T are equal in size (in bytes).

`SafeCast::cast<T: ByteSafe>(&self) -> &[T]`

Casts `Self` to a slice of `T`s, where `Self` is evenly divisible by `T`.

`SafeCast::cast_mut<T: ByteSafe>(&mut self) -> &mut [T]`

Casts `Self` to a mutable slice of `T`s, where `Self` is evenly divisible by `T`.

## Endianness

I'm not sure if it matches Rust's definition, however I think it is fine for the endianness
to be up to the user to handle. There is no safety violation by having an unexpected
endian swap, thus I'm okay with this not handling endian swaps for you. It is up
to the user to manually swap fields as they use them.

## Enforcement / Internals

To make this library easy to safely use we use a procedural macro to `#[derive(ByteSafe)]` on
a structure.

Interally we have two traits: `ByteSafe` and `SafeCast`. `ByteSafe` is the unsafe trait which is
used to specify that a type is safe for use for casting and byte-level copies to other types
marked `ByteSafe`. `SafeCast` is the trait which implements the casting/copying funtions for
a given type, if the type implements `ByteSafe`. `SafeCast` is automatically implemented for
any type which is `ByteSafe`.

The `ByteSafe` trait is the unsafe one which is either manually implemented (developer must verify
it is safe), or is automatically implemented safely by `#[derive(ByteSafe)]`.

`ByteSafe` contains a dummy function `bytesafe()` which is core to the derive implementation.
`bytesafe()` does nothing, nor does it return anything. It is simply there so that the
automatic derive can attempt to call this function to determine if the trait is implemented.

Interally the custom derive does 2 simple things.

- Verifies the structure is marked as packed
- Implements `ByteSafe` for the structure with a custom `ByteSafe::bytesafe()` which attempts to call
  `ByteSafe::bytesafe()` on every member of the structure. This behavior verifies that
  every member is marked `ByteSafe`. If all members are marked as `ByteSafe`, then the structure
  itself can also be marked as `ByteSafe`.
  
For this to all work a few manual `ByteSafe` implementations must be done on the core types we
want to allow in structures. In our case this list is `u8`, `u16`, `u32`, `u64`, `usize`, `i8`, `i16`, `i32`, `i64`, `isize`.
Further `ByteSafe` is implemented for slices `[T: ByteSafe]` and fixed-sized arrays up to and including 32-elements
`[T: ByteSafe; 0..33]`.
Our custom derive verifies that each member of the structure is either a `syn::Ty::Path` (raw type), or a `syn::Ty::Array`
(fixed sized array). Thus even though we allow slices for `ByteSafe`, they are not allowed in the structures in a custom
derive, only fixed sized arrays and raw types are.

The implementation of `ByteSafe` for slices allows for casting slices to structures, and structures back to slices. However
does not allow for slices to be used inside structures that are being cast to/from.

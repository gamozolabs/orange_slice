#[macro_use] extern crate quote;

extern crate proc_macro;
extern crate syn;

use proc_macro::TokenStream;
use quote::ToTokens;

/// Derive the ByteSafe trait for a given structure
///
/// This procedural macro ensures that all members of the structure being
/// derived as ByteSafe are also ByteSafe. It also verifies that the structure
/// contains no padding.
#[proc_macro_derive(ByteSafe)]
pub fn derive_bytesafe(input: TokenStream) -> TokenStream {
    /* Construct a string representation of the type definition */
    let s = input.to_string();

    /* Parse the string representation */
    let ast = syn::parse_derive_input(&s).unwrap();

    /* Build the impl */
    let gen = impl_derive_bytesafe(&ast);
    
    /* Return the generated impl */
    gen.parse().unwrap()
}

/// Internal implementation of the ByteSafe derive
fn impl_derive_bytesafe(ast: &syn::DeriveInput) -> quote::Tokens {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) =
        ast.generics.split_for_impl();

    let mut stuff = Vec::new();

    /* There is probably a better/cleaner way of doing this, but check if
     * this structure is marked as repr(C). If it is not repr(C) we might
     * not be able to directly copy bits as the representation could be
     * different than what we expect.
     */
    let mut is_repr_c = false;
    for attr in &ast.attrs {
        if let syn::MetaItem::List(ref ident, ref items) = attr.value {
            if ident == "repr" {
                for item in items {
                    if let &syn::NestedMetaItem::MetaItem(ref item) = item {
                        if item.name() == "C" || item.name() == "packed" {
                            is_repr_c = true;
                        }
                    }
                }
            }
        }
    }
    assert!(is_repr_c);

    /* We only support structures */
    if let syn::Body::Struct(ref variants) = ast.body {
        /* For each field in the structure call bytesafe() on it, this will
         * fail if it does not implement the bytesafe trait.
         *
         * However currently with automatic dereferencing this allows for
         * references to be used to types that are ByteSafe, which is an issue.
         * We need a workaround for this.
         */
        for field in variants.fields().iter() {
            match field.ty {
                /* We allow Path types */
                syn::Ty::Path(_, _) => {}

                /* We allow fixed sized arrays */
                syn::Ty::Array(_, _) => {}

                /* Anything else in the structure is not allowed */
                _ => panic!("Unsupported type {:?}", field.ty)
            }
            
            let mut typey = quote::Tokens::new();
            field.ty.to_tokens(&mut typey);

            //eprint!("{}\n", typey);

            /* Attempt to call bytesafe() dummy routine on member. This will
             * fail at compile time if this structure member doesn't implement
             * ByteSafe.
             */
            stuff.push(quote! {
                /* Accumulate the size of all the raw elements */
                calculated_size += core::mem::size_of::<#typey>();
                <#typey>::bytesafe();
            });
        }
    } else {
        panic!("Expected struct only for ByteSafe");
    }

    /* Implement ByteSafe! */
    quote! {
        unsafe impl #impl_generics ::safecast::ByteSafe for #name #ty_generics #where_clause {
            fn bytesafe()
            {
                /* Normalize so we can use core even in std projects */
                extern crate core;

                let mut calculated_size = 0usize;

                #(#stuff)*

                /* Validate that the size of each individual member adds up
                 * to the structure size. If this is a mismatch then there was
                 * padding in the structure and it is not safe to cast this
                 * structure.
                 */
                assert!(calculated_size == core::mem::size_of::<#name #ty_generics #where_clause>(),
                    "Structure contained padding bytes, not safe for cast");
            }
        }
    }
}


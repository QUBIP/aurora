/// We encapsulate the output of bindgen in a inner module, so we can
/// disable clippy and other lints for the generated code
#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod inner_bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod forbidden {
    use crate::bindings::ossl_param_st;

    extern "C" {
        pub fn OSSL_PARAM_set_utf8_ptr(
            p: *mut ossl_param_st,
            val: *const ::std::os::raw::c_char,
        ) -> ::std::os::raw::c_int;
    }
    extern "C" {
        pub fn OSSL_PARAM_locate(
            p: *mut ossl_param_st,
            key: *const ::std::os::raw::c_char,
        ) -> *mut ossl_param_st;
    }
}

/// Then we export as pub all the symbols from the inner module.
pub use inner_bindings::*;

use ::std::os::raw::c_int;

// Why we need to cast the function itself, in the call to `transmute`: the name
// of a function, like `OSSL_provider_teardown`, is actually a zero-sized type
// that uniquely identifies that function. It's not a pointer to it, unless you
// cast it. See:
// https://users.rust-lang.org/t/casting-function-pointers-with-different-linkage/31488/2
macro_rules! generic_non_null_fn_ptr {
    ($address:expr) => {
        std::mem::transmute::<*const (), unsafe extern "C" fn()>($address as _)
    };
}
pub(crate) use generic_non_null_fn_ptr;

pub type GenericNullableFnPtr = ::std::option::Option<unsafe extern "C" fn()>;

impl OSSL_DISPATCH {
    pub const END: Self = Self {
        function_id: 0,
        function: None,
    };

    pub fn new(fnid: c_int, fnpt: GenericNullableFnPtr) -> Self {
        Self {
            function_id: fnid,
            function: fnpt,
        }
    }
}

impl Default for OSSL_DISPATCH {
    fn default() -> Self {
        Self::END
    }
}

/// A convenience macro to quickly declare a OSSL_DISPATCH table entry
macro_rules! dispatch_table_entry {
    ( $f_id:expr, $f_name:expr ) => {
        OSSL_DISPATCH::new(
            // Why we need to cast the function ID: bindgen has to guess
            // at the type for `#define`d constants, and it guesses u32,
            // which conflicts with the type of the `function_id` field.
            $f_id as i32,
            Some(unsafe { crate::bindings::generic_non_null_fn_ptr!($f_name) }),
        )
    };
}
pub(crate) use dispatch_table_entry;

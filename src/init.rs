use std::ffi::CStr;
use std::ptr::null;

use crate::named;
use crate::OpenSSLProvider;
use libc::{c_int, c_void};
use rust_openssl_core_provider::bindings::OSSL_OP_KEM;
use rust_openssl_core_provider::{bindings, osslparams};
use bindings::forbidden;
use bindings::ossl_param_st;
use bindings::OSSL_DISPATCH;
use bindings::OSSL_PROV_PARAM_NAME;
use osslparams::OSSLParam;

use crate::{PROV_NAME, PROV_VER};

#[cfg(feature = "pretty_env_logger")]
pub use pretty_env_logger as logger;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct OSSL_CORE_HANDLE {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[named]
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn OSSL_provider_init(
    handle: *const OSSL_CORE_HANDLE,
    core_dispatch: *const OSSL_DISPATCH,
    provider_dispatch: *mut *const OSSL_DISPATCH,
    provctx: *mut *mut c_void,
) -> c_int {
    #[cfg(feature = "pretty_env_logger")]
    logger::try_init().expect("Failed initializing logger subsystem");

    trace!(target: log_target!(), "Just called a 🦀 Rust function from C!");
    trace!(target: log_target!(), "This is 🌌 {} v{}", PROV_NAME, PROV_VER);

    let mut prov = Box::new(OpenSSLProvider::new(handle, core_dispatch));
    let ourdispatch = prov.get_provider_dispatch();
    unsafe {
        *provctx = Box::into_raw(prov).cast();
        *provider_dispatch = ourdispatch;
    }
    //std::mem::forget(prov);
    trace!(target: log_target!(), "{}", "Just written to C pointers from a 🦀 Rust function!");

    1
}

#[named]
pub unsafe extern "C" fn provider_teardown(vprovctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    let /* mut */ prov: Box<OpenSSLProvider> = unsafe { Box::from_raw(vprovctx.cast()) };
    let name = prov.name;
    debug!(target: log_target!(), "Teardown of \"{name}\"");
    info!(target: log_target!(), "🦀 Goodbye!");
}

#[named]
pub unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const ossl_param_st {
    trace!(target: log_target!(), "{}", "Called!");
    let prov: &mut OpenSSLProvider<'_> = vprovctx.into();
    (*prov).get_params_array()
}

#[named]
pub unsafe extern "C" fn get_params(vprovctx: *mut c_void, params: *mut ossl_param_st) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    /* It's important to only cast the pointer, not Box it back up, because otherwise the provctx
     * object would get dropped at the end of this function (and the compiler wouldn't even warn
     * us about it, because this code is marked unsafe!). */
    let prov: &OpenSSLProvider<'_> = vprovctx.into();

    /* Here we build a vec of OSSLParam structs which are type-safe wrappers around pointers to the
     * actual C structs in the params array... */
    let mut v: Vec<OSSLParam> = Vec::new();
    let mut i = 0;
    loop {
        let p = params.offset(i);
        if (*p).key.is_null() {
            break;
        } else {
            match OSSLParam::try_from(p) {
                Ok(param) => v.push(param),
                Err(_) => eprintln!("Unimplemented param data type: {:?}", (*p).data_type),
            }
        }
        i += 1;
    }

    /* ... and then we ignore all that work and call C functions directly to write the name of the
     * provider to the appropriate C struct, because the ability to do this with the OSSLParam Rust
     * struct isn't implemented yet. */
    let p: *mut ossl_param_st = forbidden::OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME.as_ptr());
    if !p.is_null() && forbidden::OSSL_PARAM_set_utf8_ptr(p, (prov).c_prov_name().as_ptr()) == 0 {
        return 0;
    }
    1
}


use bindings::OSSL_ALGORITHM;

const MLKEM_FUNCTIONS: [OSSL_DISPATCH; 1] = [
    OSSL_DISPATCH {
        function_id: 0,
        function: None,
    },
];


pub struct ProviderContext {
    mlkemprov_ptr: Option<*const OSSL_ALGORITHM>,
}

impl ProviderContext {
    
    fn get_mlkemprov(&mut self) -> *const OSSL_ALGORITHM {
        match self.mlkemprov_ptr {
            Some(ptr) => ptr,
            None => {
                // Dynamically create the MLKEMPROV array
                let array = vec![
                    OSSL_ALGORITHM {
                        algorithm_names: c"MLKEM".as_ptr(), // Ensure proper null-terminated C string
                        property_definition: c"x.author='author'".as_ptr(), // Ensure proper null-terminated C string
                        implementation: MLKEM_FUNCTIONS.as_ptr(),
                        algorithm_description: std::ptr::null(),
                    },
                    OSSL_ALGORITHM {
                        algorithm_names: std::ptr::null(),
                        property_definition: std::ptr::null(),
                        implementation: std::ptr::null(),
                        algorithm_description: std::ptr::null(),
                    },
                ]
                .into_boxed_slice();

                let raw_ptr = Box::into_raw(array) as *const OSSL_ALGORITHM;
                self.mlkemprov_ptr = Some(raw_ptr);
                raw_ptr
            }
        }
    }
}



pub extern "C" fn query(provctx: *mut c_void,
                        operation_id: i32,
                        no_cache: *mut i32,
) -> *const OSSL_ALGORITHM {

    unsafe {
        if !no_cache.is_null() {
            *no_cache = 0;
        }
        let ctx = &mut *(provctx as *mut ProviderContext); // Cast the void pointer to ProviderContext
        match operation_id {
            x if x == OSSL_OP_KEM as i32 => ctx.get_mlkemprov(),
            _ => std::ptr::null(),
        }
    }
}
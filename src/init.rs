use crate::forge::{bindings, osslparams};
use crate::named;
use crate::OpenSSLProvider;
use bindings::forbidden;
use bindings::OSSL_DISPATCH;
use bindings::OSSL_PARAM;
use bindings::OSSL_PROV_PARAM_NAME;
use libc::{c_int, c_void};
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
pub unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");

    let prov: &mut OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };
    prov.get_params_array()
}

#[named]
pub unsafe extern "C" fn get_params(vprovctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");
    /* It's important to only cast the pointer, not Box it back up, because otherwise the provctx
     * object would get dropped at the end of this function (and the compiler wouldn't even warn
     * us about it, because this code is marked unsafe!). */
    let prov: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

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
    let p: *mut OSSL_PARAM = forbidden::OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME.as_ptr());
    if !p.is_null() && forbidden::OSSL_PARAM_set_utf8_ptr(p, (prov).c_prov_name().as_ptr()) == 0 {
        return 0;
    }
    1
}

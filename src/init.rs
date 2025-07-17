use crate::forge::{bindings, osslparams};
use crate::named;
use crate::Error as OurError;
use crate::OpenSSLProvider;
use bindings::OSSL_DISPATCH;
use bindings::OSSL_PARAM;
use bindings::{OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION};
use libc::{c_int, c_void};
use osslparams::OSSLParam;
use std::sync::Once;

use crate::{PROV_NAME, PROV_VER};

#[cfg(feature = "env_logger")]
pub use env_logger as logger;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct OSSL_CORE_HANDLE {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[cfg(feature = "env_logger")]
fn inner_try_init_logging() -> Result<(), OurError> {
    logger::Builder::from_default_env()
        //.filter_level(log::LevelFilter::Debug)
        .format_timestamp(None) // Optional: disable timestamps
        .format_module_path(false) // Optional: disable module path
        .format_target(true) // Optional: enable target
        .format_source_path(true)
        .is_test(cfg!(test))
        .try_init()
        .map_err(OurError::from)
}

pub(crate) fn try_init_logging() -> Result<(), OurError> {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        #[cfg(feature = "env_logger")]
        inner_try_init_logging().expect("Failed to initialize the logging system");
    });

    Ok(())
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
    #[cfg(feature = "env_logger")]
    try_init_logging().expect("Failed initializing logger subsystem");

    trace!(target: log_target!(), "Just called a 🦀 Rust function from C!");
    trace!(target: log_target!(), "This is 🌌 {} v{}", PROV_NAME, PROV_VER);

    // convert the upcall table to a slice for easier handling
    let core_dispatch_slice = if !core_dispatch.is_null() {
        let mut i: usize = 0;
        loop {
            let f = unsafe { *core_dispatch.offset(i as isize) };
            if f.function_id == OSSL_DISPATCH::END.function_id {
                break;
            }
            assert!(
                i < 512,
                "the core_dispatch table seems to be excessively long, bailing!"
            );
            i += 1;
        }
        unsafe { std::slice::from_raw_parts(core_dispatch, i) }
    } else {
        error!("Got a null core_dispatch table");
        unreachable!("Got a null core_dispatch table");
    };

    let mut prov = Box::new(OpenSSLProvider::new(handle, core_dispatch_slice));

    // FIXME: the following block should actually be done by adapters and individual enabled algorithms,
    // we are doing it here now just for rapid development and debugging
    {
        let objects = vec![(
            c"2.16.840.1.101.3.4.3.18",
            c"ML-DSA-65",
            c"id-ml-dsa-65",
            None,
        )];
        for (oid, sn, ln, digest_name) in objects {
            match prov.OBJ_create(oid, sn, ln) {
                Ok(_) => {
                    debug!(target: log_target!(), "Registered OBJ_create({oid:?},{sn:?},{ln:?})");
                }
                Err(e) => {
                    error!(target: log_target!(), "Failed to OBJ_create({oid:?},{sn:?},{ln:?}): {e:?}");
                    continue;
                }
            }

            let sign_name = oid;
            let pkey_name = ln;
            match prov.OBJ_add_sigid(sign_name, digest_name, pkey_name) {
                Ok(_) => {
                    debug!(target: log_target!(), "Registered OBJ_add_sigid({sign_name:?}, {digest_name:?}, {pkey_name:?})");
                }
                Err(e) => {
                    error!(target: log_target!(), "Failed to OBJ_add_sigid({sign_name:?}, {digest_name:?}, {pkey_name:?}): {e:?}");
                    continue;
                }
            }
        }
    }

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
    trace!(target: log_target!(), "Teardown of \"{name}\"");
    trace!(target: log_target!(), "🦀 Goodbye!");
}

#[named]
pub unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const FAILURE: *const OSSL_PARAM = std::ptr::null();

    trace!(target: log_target!(), "{}", "Called!");

    let prov: &mut OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return FAILURE;
        }
    };
    prov.get_params_array()
}

#[named]
pub unsafe extern "C" fn get_params(vprovctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int {
    const FAILURE: c_int = 0;
    const SUCCESS: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");

    /* It's important to only cast the pointer, not Box it back up, because otherwise the provctx
     * object would get dropped at the end of this function (and the compiler wouldn't even warn
     * us about it, because this code is marked unsafe!). */
    let prov: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return FAILURE;
        }
    };

    let params = match OSSLParam::try_from(params) {
        Ok(params) => params,
        Err(e) => {
            error!(target: log_target!(), "Failed decoding params: {:?}", e);
            return FAILURE;
        }
    };

    for mut p in params {
        let key = match p.get_key() {
            Some(key) => key,
            None => {
                error!(target: log_target!(), "Param without valid key {:?}", p);
                return FAILURE;
            }
        };

        if key == OSSL_PROV_PARAM_NAME {
            let str = prov.c_prov_name();

            match p.set(str) {
                Ok(_) => (),
                Err(e) => {
                    error!(target: log_target!(), "Cannot set OSSL_PROV_PARAM_NAME {p:?}: {e:?}");
                    return FAILURE;
                }
            }
        } else if key == OSSL_PROV_PARAM_VERSION {
            let str = prov.c_prov_version();

            match p.set(str) {
                Ok(_) => (),
                Err(e) => {
                    error!(target: log_target!(), "Cannot set OSSL_PROV_PARAM_VERSION {p:?}: {e:?}");
                    return FAILURE;
                }
            }
        } else if key == OSSL_PROV_PARAM_BUILDINFO {
            let str = prov.c_prov_buildinfo();

            match p.set(str) {
                Ok(_) => (),
                Err(e) => {
                    error!(target: log_target!(), "Cannot set OSSL_PROV_PARAM_BUILDINFO {p:?}: {e:?}");
                    return FAILURE;
                }
            }
        }
    }
    SUCCESS
}

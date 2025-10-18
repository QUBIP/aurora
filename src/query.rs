use std::ffi::CStr;

use crate::forge;
use crate::named;
use crate::ProviderInstance;
use forge::bindings;
use forge::ossl_callback::OSSLCallback;
use libc::{c_char, c_int, c_void};

use bindings::{OSSL_ALGORITHM, OSSL_CALLBACK};

#[named]
pub(crate) extern "C" fn query_operation(
    vprovctx: *mut c_void,
    operation_id: i32,
    no_cache: *mut i32,
) -> *const OSSL_ALGORITHM {
    trace!(target: log_target!(), "{}", "Called!");

    let provctx: &mut ProviderInstance<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return std::ptr::null();
        }
    };
    if !no_cache.is_null() {
        unsafe {
            *no_cache = 0;
        }
    }

    match provctx
        .adapters_ctx
        .get_algorithms_by_op_id(operation_id as u32)
    {
        Some(algorithms) => algorithms,
        None => {
            trace!(target: log_target!(), "Unsupported operation_id: {}", operation_id);
            std::ptr::null()
        }
    }
}

#[named]
pub(crate) extern "C" fn get_capabilities(
    vprovctx: *mut c_void,
    capability: *const c_char,
    cb: OSSL_CALLBACK,
    arg: *mut c_void,
) -> c_int {
    const FAILURE: c_int = 0;
    const SUCCESS: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");

    let provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return FAILURE;
        }
    };

    let capability = if capability.is_null() {
        error!(target: log_target!(), "Passed NULL capability");
        return FAILURE;
    } else {
        unsafe { CStr::from_ptr(capability) }
    };

    let cb = match OSSLCallback::try_new(cb, arg) {
        Ok(cb) => cb,
        Err(e) => {
            error!(target: log_target!(), "{e:?}");
            return FAILURE;
        }
    };

    match provctx.adapters_ctx.get_capabilities(capability) {
        Some(params_lists) => {
            for params_list in params_lists {
                trace!(target: log_target!(), "Calling cb({params_list:0x?})");
                let ret = unsafe { cb.call_raw(params_list) };
                trace!(target: log_target!(), "cb({params_list:0x?}) returned {ret:?}");
                if ret == 0 {
                    trace!(target: log_target!(), "Callback returned 0");
                    return FAILURE;
                }
            }
            trace!(target: log_target!(), "Iterated over all params list. Returning SUCCESS");
            return SUCCESS;
        }
        None => {
            debug!(target: log_target!(), "Unknown capability: {capability:?}");
            return SUCCESS;
        }
    }
}

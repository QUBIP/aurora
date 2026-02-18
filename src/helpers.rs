#![allow(dead_code)]
#![allow(unused_macros)]

use super::*;
pub(crate) use ::function_name::named;

/// Match on a `Result`, evaluating to the wrapped value if it is `Ok` or
/// returning `ERROR_RET` (which must already be defined) if it is `Err`.
///
/// This macro should be used in `extern "C"` functions that will be directly
/// called by OpenSSL. In other functions, `Result`s should be handled in the
/// usual Rust way.
///
/// If invoked with an `Err` value, this macro also calls [`log::error!`] to log
/// the error.
///
/// Before invoking this macro, an identifier `ERROR_RET` must be in scope, and
/// the type of its value must be the same as (or coercible to) the return type
/// of the function in which `handleResult!` is being invoked.
macro_rules! handleResult {
    ($e:expr) => { match ($e)
        {
            Ok(r) => r,
            Err(e) => {
                error!(target: $crate::helpers::log_target!(), "{:#?}", e);
                return ERROR_RET;
            }
        }
    };
}
pub(crate) use handleResult;

macro_rules! function_path {
    () => {
        concat!(module_path!(), "::", function_name!(), "()")
    };
}
pub(crate) use function_path;

macro_rules! log_target {
    () => {
        $crate::helpers::function_path!()
    };
}
pub(crate) use log_target;

mod init_logging {
    #[cfg(feature = "env_logger")]
    pub(super) use ::env_logger as logger;

    #[cfg(feature = "env_logger")]
    pub(super) fn inner_try_init_logging() -> Result<(), crate::Error> {
        logger::Builder::from_default_env()
            //.filter_level(log::LevelFilter::Debug)
            .format_timestamp(None) // Optional: disable timestamps
            .format_module_path(false) // Optional: disable module path
            .format_target(true) // Optional: enable target
            .format_source_path(true)
            .is_test(cfg!(test))
            .try_init()
            .map_err(crate::Error::from)
    }
}

pub(crate) fn try_init_logging() -> Result<(), crate::Error> {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        #[cfg(feature = "env_logger")]
        init_logging::inner_try_init_logging().expect("Failed to initialize the logging system");
    });

    Ok(())
}

#[named]
pub(super) fn examine_core_parameters(
    upcaller: &CoreDispatchWithCoreHandle<'_>,
) -> Result<(), crate::Error> {
    use crate::bindings::{
        c_void, CONST_OSSL_PARAM, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UTF8_PTR,
        OSSL_PROV_PARAM_CORE_PROV_NAME, OSSL_PROV_PARAM_CORE_VERSION,
    };

    const CAPACITY: usize = 4;
    let mut data_ptrs = [std::ptr::null_mut(); CAPACITY];
    let mut param_list_vec = Vec::<CONST_OSSL_PARAM>::with_capacity(CAPACITY);

    let core_params = upcaller.CORE_gettable_params().expect("Should not fail");
    for (counter, i) in core_params.into_iter().enumerate() {
        let key = i.get_key().unwrap();
        let t = i.get_data_type().unwrap();
        trace!(target: log_target!(), "Gettable CORE Parameter {key:?} of type {t:?}");

        let data = (&mut data_ptrs[counter] as *mut *mut c_void).cast();

        let o = CONST_OSSL_PARAM {
            key: key.as_ptr(),
            data_type: t,
            data,
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        };
        param_list_vec.push(o);
    }
    param_list_vec.push(CONST_OSSL_PARAM::END);

    let param_list = param_list_vec.first().unwrap().try_into().unwrap();
    upcaller
        .CORE_get_params(param_list)
        .expect("Failed to retrieve core parameters");

    let param_list: OSSLParam<'_> = param_list_vec.first().unwrap().try_into().unwrap();
    for i in param_list {
        let key = i.get_key().unwrap();
        let t = i.get_data_type().unwrap();

        match (key, t) {
            (k, OSSL_PARAM_UTF8_PTR) if k == OSSL_PROV_PARAM_CORE_VERSION => {
                let data = i.get::<&CStr>().expect("Could not parse version string");
                debug!(target: log_target!(), "OpenSSL Core reports being version {data:?}");
            }
            (k, OSSL_PARAM_UTF8_PTR) if k == OSSL_PROV_PARAM_CORE_PROV_NAME => {
                let data = i
                    .get::<&CStr>()
                    .expect("Could not parse provider name string");
                debug!(target: log_target!(), "OpenSSL Core reports the name of this provider being {data:?}");
            }
            (k, OSSL_PARAM_UTF8_PTR) => {
                let data = i.get::<&CStr>();
                debug!(target: log_target!(), "{k:?}={data:?}");
            }
            (k, _) => {
                debug!(target: log_target!(), "{k:?}={i:?}");
            }
        }
    }
    Ok(())
}

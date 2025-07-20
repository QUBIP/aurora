#[macro_use]
extern crate log;

pub(crate) use ::function_name::named;
use std::ffi::{CStr, CString};
use std::sync::{LazyLock, OnceLock};
use zeroize::{Zeroize, Zeroizing};

pub type Error = anyhow::Error;

macro_rules! function_path {
    () => {
        concat!(module_path!(), "::", function_name!(), "()")
    };
}

macro_rules! log_target {
    () => {
        function_path!()
    };
}

pub(crate) mod forge;
use forge::{bindings, osslparams};
pub(crate) mod adapters;
mod init;
mod query;
pub(crate) mod random;
mod upcalls;

pub(crate) mod asn_definitions;

#[cfg(test)]
pub(crate) mod tests;

pub use crate::upcalls::{CoreDispatch, CoreDispatchWithCoreHandle};
use bindings::dispatch_table_entry;
use bindings::OSSL_PARAM;
use bindings::{
    OSSL_FUNC_provider_get_capabilities_fn, OSSL_FUNC_provider_get_params_fn,
    OSSL_FUNC_provider_gettable_params_fn, OSSL_FUNC_provider_query_operation_fn,
    OSSL_FUNC_provider_teardown_fn, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_GET_CAPABILITIES, OSSL_FUNC_PROVIDER_GET_PARAMS,
    OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN, OSSL_PROV_PARAM_BUILDINFO,
    OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION,
};
use init::OSSL_CORE_HANDLE;
use osslparams::{OSSLParam, OSSLParamData, Utf8PtrData, OSSL_PARAM_END};
use upcalls::traits::{CoreUpcaller, CoreUpcallerWithCoreHandle};

/// This is an abstract representation of one Provider instance.
/// Remember that a single provider module could be loaded multiple
/// times within the same process, either in the same OpenSSL libctx or
/// within different libctx's.
///
/// At the moment a single instance holds nothing of relevance, but in
/// the future all the context which is specific to an instance should
/// be encapsulated within it, so that different instances could have
/// different configurations, and their own separate state.
#[derive(Debug)]
pub struct OpenSSLProvider<'a> {
    pub data: [u8; 10],
    core_handle: *const OSSL_CORE_HANDLE,
    core_dispatch: CoreDispatch<'a>,
    pub name: &'a str,
    pub version: &'a str,
    params: Vec<OSSLParam<'a>>,
    param_array_ptr: Option<*mut [OSSL_PARAM]>,
    pub(crate) adapters_ctx: adapters::FinalizedAdaptersHandle,
}

/// We implement the Drop trait to make it explicit when a provider
/// instance is dropped: this should only happen after `teardown()` has
/// been called.
impl<'a> Drop for OpenSSLProvider<'a> {
    #[named]
    fn drop(&mut self) {
        let tname = std::any::type_name_of_val(self);
        let name = self.name;
        trace!(
            target: log_target!(),
            "🗑️\tDropping {tname} named {name}",
        )
    }
}

pub static PROV_NAME: &str = env!("CARGO_PKG_NAME");
pub static PROV_VER: &str = env!("CARGO_PKG_VERSION");
pub static PROV_BUILDINFO: &str = env!("CARGO_GIT_DESCRIBE");

impl<'a> OpenSSLProvider<'a> {
    pub fn new(handle: *const OSSL_CORE_HANDLE, core_dispatch: CoreDispatch<'a>) -> Self {
        let upcaller: CoreDispatchWithCoreHandle<'a> = (core_dispatch, handle).into();

        let adapters_ctx = { adapters::FinalizedAdaptersHandle::new(&upcaller) };

        let core_dispatch: CoreDispatch = upcaller.into();

        Self {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            core_handle: handle,
            core_dispatch,
            name: PROV_NAME,
            version: PROV_VER,
            param_array_ptr: None,
            params: vec![
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_NAME)),
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_VERSION)),
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_BUILDINFO)),
            ],
            adapters_ctx,
        }
    }

    /// Retrieve a heap allocated `OSSL_DISPATCH` table associated with this provider instance.
    pub fn get_provider_dispatch(&mut self) -> *const OSSL_DISPATCH {
        let ret = Box::new([
            dispatch_table_entry!(
                OSSL_FUNC_PROVIDER_TEARDOWN,
                OSSL_FUNC_provider_teardown_fn,
                crate::init::provider_teardown
            ),
            dispatch_table_entry!(
                OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
                OSSL_FUNC_provider_gettable_params_fn,
                crate::init::gettable_params
            ),
            dispatch_table_entry!(
                OSSL_FUNC_PROVIDER_GET_PARAMS,
                OSSL_FUNC_provider_get_params_fn,
                crate::init::get_params
            ),
            dispatch_table_entry!(
                OSSL_FUNC_PROVIDER_QUERY_OPERATION,
                OSSL_FUNC_provider_query_operation_fn,
                crate::query::query_operation
            ),
            dispatch_table_entry!(
                OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
                OSSL_FUNC_provider_get_capabilities_fn,
                crate::query::get_capabilities
            ),
            OSSL_DISPATCH::END,
        ]);
        Box::into_raw(ret).cast()
    }

    fn get_params_array(&mut self) -> *const OSSL_PARAM {
        // This is kind of like a poor man's std::sync::Once
        let raw_ptr = match self.param_array_ptr {
            Some(raw_ptr) => raw_ptr,
            None => {
                let slice = self
                    .params
                    .iter_mut()
                    .map(|p| unsafe { *p.get_c_struct() })
                    .chain(std::iter::once(OSSL_PARAM_END))
                    .collect::<Vec<_>>()
                    .into_boxed_slice();
                let raw_ptr = Box::into_raw(slice);
                self.param_array_ptr = Some(raw_ptr);
                raw_ptr
            }
        };
        raw_ptr.cast()
    }

    pub fn c_prov_name(&self) -> &CStr {
        #[expect(clippy::let_and_return)]
        static L: LazyLock<CString> = LazyLock::new(|| {
            let _s = CString::new(crate::PROV_NAME).expect("Error parsing cPROV_NAME");
            _s
        });
        L.as_ref()
    }

    pub fn c_prov_version(&self) -> &CStr {
        #[expect(clippy::let_and_return)]
        static L: LazyLock<CString> = LazyLock::new(|| {
            let _s = CString::new(crate::PROV_VER).expect("Error parsing cPROV_VER");
            _s
        });
        L.as_ref()
    }

    pub fn c_prov_buildinfo(&self) -> &CStr {
        #[expect(clippy::let_and_return)]
        static L: LazyLock<CString> = LazyLock::new(|| {
            let _s = CString::new(crate::PROV_BUILDINFO).expect("Error parsing cPROV_BUILDINFO");
            _s
        });
        L.as_ref()
    }
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &mut OpenSSLProvider<'a> {
    type Error = Error;

    #[named]
    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut core::ffi::c_void> for &mut OpenSSLProvider<'a>"
        );
        let provp = vctx as *mut OpenSSLProvider;
        if provp.is_null() {
            return Err(anyhow::anyhow!("vctx was null"));
        }
        Ok(unsafe { &mut *provp })
    }
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &OpenSSLProvider<'a> {
    type Error = Error;

    #[named]
    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}", "impl<'a> TryFrom<*mut core::ffi::c_void> for &OpenSSLProvider<'a>");
        let r: &mut OpenSSLProvider<'a> = vctx.try_into()?;
        Ok(r)
    }
}

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
#[macro_export]
macro_rules! handleResult {
    ($e:expr) => { match ($e)
        {
            Ok(r) => r,
            Err(e) => {
                error!(target: log_target!(), "{:#?}", e);
                return ERROR_RET;
            }
        }
    };
    //($e:expr, $errhandler:expr) => { match ($e)
    //    {
    //        Ok(r) => r,
    //        Err(e) => {
    //            errhandler
    //        }
    //    }
    //};
}

impl CoreUpcaller for OpenSSLProvider<'_> {
    fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()> {
        self.core_dispatch.fn_from_core_dispatch(id)
    }
}

impl CoreUpcallerWithCoreHandle for OpenSSLProvider<'_> {
    fn get_core_handle(&self) -> *const OSSL_CORE_HANDLE {
        self.core_handle
    }
}

pub mod traits {
    pub use super::upcalls::traits::{CoreUpcaller, CoreUpcallerWithCoreHandle};
}

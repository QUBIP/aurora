#[macro_use]
extern crate log;

use ::function_name::named;
use std::ffi::{CStr, CString};
use std::sync::LazyLock;

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

use rust_openssl_core_provider::{bindings, osslparams};
pub(crate) mod adapters;
mod init;
mod query;

use bindings::dispatch_table_entry;
use bindings::ossl_param_st;
use bindings::{
    OSSL_FUNC_provider_get_params_fn, OSSL_FUNC_provider_gettable_params_fn,
    OSSL_FUNC_provider_query_operation_fn, OSSL_FUNC_provider_teardown_fn, OSSL_DISPATCH,
    OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, OSSL_FUNC_PROVIDER_GET_PARAMS,
    OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN, OSSL_PROV_PARAM_NAME,
};
use init::OSSL_CORE_HANDLE;
use osslparams::{OSSLParam, OSSLParamData, Utf8PtrData, OSSL_PARAM_END};

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
    _handle: *const OSSL_CORE_HANDLE,
    _core_dispatch: *const OSSL_DISPATCH,
    pub name: &'a str,
    pub version: &'a str,
    params: Vec<OSSLParam>,
    param_array_ptr: Option<*mut [ossl_param_st]>,
    pub(crate) adapters_ctx: adapters::Contexts,
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

impl<'a> OpenSSLProvider<'a> {
    pub fn new(handle: *const OSSL_CORE_HANDLE, core_dispatch: *const OSSL_DISPATCH) -> Self {
        Self {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            _handle: handle,
            _core_dispatch: core_dispatch,
            name: PROV_NAME,
            version: PROV_VER,
            param_array_ptr: None,
            params: vec![OSSLParam::Utf8Ptr(Utf8PtrData::new_null(
                OSSL_PROV_PARAM_NAME,
            ))],
            adapters_ctx: adapters::Contexts::default(),
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
            OSSL_DISPATCH::END,
        ]);
        ret.as_ptr()
    }

    fn get_params_array(&mut self) -> *const ossl_param_st {
        // This is kind of like a poor man's std::sync::Once
        let raw_ptr = match self.param_array_ptr {
            Some(raw_ptr) => raw_ptr,
            None => {
                let slice = self
                    .params
                    .clone()
                    .into_iter()
                    .map(|p| (unsafe { *p.get_c_struct() }))
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
        // FIXME: this should be turned into `expect` or removed
        #[allow(clippy::let_and_return)]
        static L: LazyLock<CString> = LazyLock::new(|| {
            let _s = CString::new(crate::PROV_NAME).expect("Error parsing cPROV_NAME");
            _s
        });
        L.as_ref()
    }
}

impl<'a> From<*mut core::ffi::c_void> for &mut OpenSSLProvider<'a> {
    #[named]
    fn from(vctx: *mut core::ffi::c_void) -> Self {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut core::ffi::c_void> for &mut OpenSSLProvider<'a>"
        );
        let provp = vctx as *mut OpenSSLProvider;
        if provp.is_null() {
            panic!("vctx was null");
        }
        unsafe { &mut *provp }
    }
}

impl<'a> From<*mut core::ffi::c_void> for &OpenSSLProvider<'a> {
    #[named]
    fn from(vctx: *mut core::ffi::c_void) -> Self {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut core::ffi::c_void> for &OpenSSLProvider<'a>"
        );
        let provp = vctx as *const OpenSSLProvider;
        if provp.is_null() {
            panic!("vctx was null");
        }
        unsafe { &*provp }
    }
}

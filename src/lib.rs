#[macro_use]
extern crate log;

pub(crate) use ::function_name::named;
use std::ffi::{c_int, c_void, CStr, CString};
use std::sync::LazyLock;

pub type Error = anyhow::Error;
use anyhow::anyhow;

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

use forge::{bindings, osslparams};
pub use openssl_provider_forge as forge;
pub(crate) mod adapters;
mod init;
mod query;
pub(crate) mod random;

#[cfg(test)]
pub(crate) mod tests;

use bindings::dispatch_table_entry;
use bindings::OSSL_PARAM;
use bindings::{
    OSSL_FUNC_provider_get_capabilities_fn, OSSL_FUNC_provider_get_params_fn,
    OSSL_FUNC_provider_gettable_params_fn, OSSL_FUNC_provider_query_operation_fn,
    OSSL_FUNC_provider_teardown_fn, OSSL_CORE_BIO, OSSL_DISPATCH, OSSL_FUNC_BIO_READ_EX,
    OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN,
    OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION,
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
    _core_dispatch: &'a [OSSL_DISPATCH],
    pub name: &'a str,
    pub version: &'a str,
    params: Vec<OSSLParam<'a>>,
    param_array_ptr: Option<*mut [OSSL_PARAM]>,
    pub(crate) adapters_ctx: adapters::AdaptersHandle,
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
    pub fn new(handle: *const OSSL_CORE_HANDLE, core_dispatch: *const OSSL_DISPATCH) -> Self {
        // convert the upcall table to a slice so we can use it more easily
        let core_dispatch_slice = if !core_dispatch.is_null() {
            let mut i: usize = 0;
            // this check is basically "while core_dispatch[i] != OSSL_DISPATCH_END"; for some reason,
            // OSSL_DISPATCH structs can't be directly compared for (in)equality
            while unsafe { *core_dispatch.offset(i as isize) }.function_id != 0 {
                i += 1;
            }
            unsafe { std::slice::from_raw_parts(core_dispatch, i) }
        } else {
            &[]
        };
        Self {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            _handle: handle,
            _core_dispatch: core_dispatch_slice,
            name: PROV_NAME,
            version: PROV_VER,
            param_array_ptr: None,
            params: vec![
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_NAME)),
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_VERSION)),
                OSSLParam::Utf8Ptr(Utf8PtrData::new_null(OSSL_PROV_PARAM_BUILDINFO)),
            ],
            adapters_ctx: adapters::AdaptersHandle::default(),
        }
        // it's not ideal that here we return an object which is in an "invalid" state bc the
        // adapters haven't been initialized yet
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

    #[allow(dead_code)]
    #[allow(non_snake_case)]
    pub(crate) fn BIO_read_ex(&self, bio: *mut OSSL_CORE_BIO) -> Result<Vec<u8>, Error> {
        // TODO we should cache the extracted function pointer somewhere in the provider context,
        // so we can just call it instead of having to dig it out like this every time
        let d = self
            ._core_dispatch
            .iter()
            .find(|&&d| d.function_id == OSSL_FUNC_BIO_READ_EX as c_int)
            .ok_or(anyhow!(
                "No entry found for BIO_read_ex() in core dispatch table"
            ))?;
        let fn_ptr = d.function.ok_or(anyhow!(
            "No function pointer available in BIO_read_ex()'s dispatch table entry"
        ))?;
        // is there a way to just specify the type using the type alias OSSL_FUNC_BIO_read_ex_fn
        // instead of writing it all out again?
        let ffi_BIO_read_ex = unsafe {
            std::mem::transmute::<
                *const (),
                unsafe extern "C" fn(
                    bio: *mut OSSL_CORE_BIO,
                    data: *mut c_void,
                    data_len: usize,
                    bytes_read: *mut usize,
                ) -> c_int,
            >(fn_ptr as _)
        };
        // we might want to tweak this depending on what size data we're usually using it for
        const DATA_LEN: usize = 2048;
        let mut data: [u8; DATA_LEN] = [0; DATA_LEN];
        let mut bytes_read: usize = 0;
        let mut bytes = Vec::new();
        loop {
            let ret = unsafe {
                ffi_BIO_read_ex(
                    bio,
                    data.as_mut_ptr() as *mut c_void,
                    DATA_LEN,
                    &mut bytes_read,
                )
            };
            if bytes_read == 0 || ret != 1 {
                break;
            }
            bytes.extend_from_slice(&data[0..bytes_read]);
        }
        Ok(bytes)
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

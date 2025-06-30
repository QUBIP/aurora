#[macro_use]
extern crate log;

pub(crate) use ::function_name::named;
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
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

pub(crate) mod asn_definitions;

#[cfg(test)]
pub(crate) mod tests;

use bindings::dispatch_table_entry;
use bindings::OSSL_PARAM;
use bindings::{
    OSSL_FUNC_provider_get_capabilities_fn, OSSL_FUNC_provider_get_params_fn,
    OSSL_FUNC_provider_gettable_params_fn, OSSL_FUNC_provider_query_operation_fn,
    OSSL_FUNC_provider_teardown_fn, OSSL_CORE_BIO, OSSL_DISPATCH, OSSL_FUNC_BIO_READ_EX,
    OSSL_FUNC_BIO_WRITE_EX, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_GET_CAPABILITIES, OSSL_FUNC_PROVIDER_GET_PARAMS,
    OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN, OSSL_PROV_PARAM_BUILDINFO,
    OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION,
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
    #[expect(dead_code)]
    core_dispatch_slice: &'a [OSSL_DISPATCH],
    core_dispatch_map: HashMap<u32, &'a OSSL_DISPATCH>,
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
    pub fn new(handle: *const OSSL_CORE_HANDLE, core_dispatch_slice: &'a [OSSL_DISPATCH]) -> Self {
        let mut core_dispatch_map = HashMap::with_capacity(core_dispatch_slice.len());
        for entry in core_dispatch_slice {
            core_dispatch_map.insert(entry.function_id as u32, entry);
        }
        Self {
            data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
            _handle: handle,
            core_dispatch_slice,
            core_dispatch_map,
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

    fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()> {
        let f = self.core_dispatch_map.get(&id).map(|f| f.function);
        match f {
            Some(Some(f)) => Some(f),
            Some(None) => {
                error!("core_dispatch entry for function_id {id:} was NULL");
                None
            }
            None => {
                warn!("no entry in core_dispatch for function_id {id:}");
                None
            }
        }
    }

    #[allow(dead_code)]
    #[expect(non_snake_case)]
    /// Makes a BIO_read_ex() core upcall.
    ///
    /// Refer to [BIO_read_ex(3ossl)](https://docs.openssl.org/3.5/man3/BIO_read/).
    pub(crate) fn BIO_read_ex(&self, bio: *mut OSSL_CORE_BIO) -> Result<Box<[u8]>, Error> {
        static CELL: OnceLock<Option<unsafe extern "C" fn()>> = OnceLock::new();
        let fn_ptr = CELL.get_or_init(|| {
            let f = self.fn_from_core_dispatch(OSSL_FUNC_BIO_READ_EX);
            f
        });
        let fn_ptr = match fn_ptr {
            Some(f) => f,
            None => {
                return Err(anyhow::anyhow!("No upcall pointer"));
            }
        };

        // FIXME: is there a way to just specify the type using the type alias OSSL_FUNC_BIO_read_ex_fn
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
            >(*fn_ptr as _)
        };

        // We use a mutable Vec to buffer reads, so we can do big reads on the heap and minimize calls
        // we might want to tweak the capacity depending on what size data we're usually using it for
        let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![42; 8 * 1024 * 1024]);
        let mut bytes_read: usize = 0;

        let mut ret_buffer: Vec<u8> = Vec::new();

        const MAX_ITERATIONS: usize = 10;
        let mut cnt: usize = 0;
        loop {
            cnt += 1;
            let ret = unsafe {
                ffi_BIO_read_ex(
                    bio,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.capacity(),
                    &mut bytes_read,
                )
            };
            match (ret, bytes_read) {
                (0, 0) => {
                    debug!("Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes => stopping for EOF");
                    break;
                }
                (0, _n) => {
                    warn!("Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                }
                (1, 0) => {
                    warn!("Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                }
                (1, _n) => {
                    debug!("Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes => 👍");
                }
                (_r, _n) => {
                    error!("Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                }
            };
            if cnt > MAX_ITERATIONS {
                error!(
                    "Reached {cnt:} upcalls to BIO_read_ex => stopping due to too many attempts"
                );
                ret_buffer.zeroize();
                return Err(anyhow::anyhow!(
                    "Underlying upcall to BIO_read_ex called too many times"
                ));
            }
            ret_buffer.extend_from_slice(&buffer[0..bytes_read]);
        }
        Ok(ret_buffer.into_boxed_slice())
    }

    #[allow(dead_code)]
    #[expect(non_snake_case)]
    #[named]
    /// Makes a BIO_write_ex() core upcall.
    ///
    /// Refer to [BIO_write_ex(3ossl)](https://docs.openssl.org/3.2/man3/BIO_write/).
    pub(crate) fn BIO_write_ex(
        &self,
        bio: *mut OSSL_CORE_BIO,
        data: &[u8],
    ) -> Result<usize, Error> {
        static CELL: OnceLock<Option<unsafe extern "C" fn()>> = OnceLock::new();
        let fn_ptr = CELL.get_or_init(|| {
            let f = self.fn_from_core_dispatch(OSSL_FUNC_BIO_WRITE_EX);
            f
        });
        let fn_ptr = match fn_ptr {
            Some(f) => f,
            None => {
                error!(target: log_target!(), "Unable to retrieve BIO_write_ex() upcall pointer");
                return Err(anyhow::anyhow!("No BIO_write_ex() upcall pointer"));
            }
        };

        // FIXME: is there a way to just specify the type using the type alias OSSL_FUNC_BIO_read_ex_fn
        // instead of writing it all out again?
        let ffi_BIO_write_ex = unsafe {
            std::mem::transmute::<
                *const (),
                unsafe extern "C" fn(
                    bio: *mut OSSL_CORE_BIO,
                    data: *const c_void,
                    data_len: usize,
                    written: *mut usize,
                ) -> c_int,
            >(*fn_ptr as _)
        };

        const MAX_ITERATIONS: usize = 10;
        let mut cnt: usize = 0;
        let mut total_bytes_written: usize = 0;
        let mut remaining = data;
        while !remaining.is_empty() {
            let mut bytes_written: usize = 0;
            cnt += 1;
            let ret = unsafe {
                ffi_BIO_write_ex(
                    bio,
                    remaining.as_ptr() as *const c_void,
                    remaining.len(),
                    &mut bytes_written,
                )
            };
            match (ret, bytes_written) {
                (0, 0) => {
                    debug!("Underlying upcall #{cnt:} to BIO_write_ex returned {ret:} after {bytes_written:} bytes => stopping for EOF");
                    break;
                }
                (0, n) => {
                    total_bytes_written += n;
                    let (_, rest) = remaining.split_at(n);
                    remaining = rest;
                    warn!("Underlying upcall #{cnt:} to BIO_write_ex returned {ret:} after {n:} more bytes (written so far: {total_bytes_written:})");
                }
                (1, 0) => {
                    warn!("Underlying upcall #{cnt:} to BIO_write_ex returned {ret:} after 0 more bytes (written so far: {total_bytes_written:})");
                }
                (1, n) => {
                    total_bytes_written += n;
                    let (_, rest) = remaining.split_at(n);
                    remaining = rest;
                    debug!("Underlying upcall #{cnt:} to BIO_write_ex returned {ret:} after {n:} more bytes  (written so far: {total_bytes_written:}) => 👍");
                }
                (r, n) => {
                    total_bytes_written += n;
                    let (_, rest) = remaining.split_at(n);
                    remaining = rest;
                    error!("Underlying upcall #{cnt:} to BIO_write_ex returned {r:} after {n:} more bytes (written so far: {total_bytes_written:})");
                }
            };
            if cnt > MAX_ITERATIONS {
                error!(
                    "Reached {cnt:} upcalls to BIO_write_ex => stopping due to too many attempts"
                );
                return Err(anyhow::anyhow!(
                    "Underlying upcall to BIO_write_ex called too many times"
                ));
            }
        }
        Ok(total_bytes_written)
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

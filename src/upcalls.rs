use super::*;
use anyhow::anyhow;
use bindings::ffi_c_types::{c_char, c_int, c_void, CStr};
use bindings::{
    OSSL_CORE_BIO, OSSL_DISPATCH, OSSL_FUNC_BIO_READ_EX, OSSL_FUNC_BIO_WRITE_EX,
    OSSL_FUNC_CORE_OBJ_ADD_SIGID, OSSL_FUNC_CORE_OBJ_CREATE,
};
#[cfg(not(test))]
use std::collections::HashMap;

pub mod traits {
    use super::*;

    pub trait CoreUpcaller {
        fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()>;

        #[expect(non_snake_case)]
        #[named]
        /// Makes a BIO_read_ex() core upcall.
        ///
        /// Refer to [BIO_read_ex(3ossl)](https://docs.openssl.org/3.5/man3/BIO_read/).
        fn BIO_read_ex(&self, bio: *mut OSSL_CORE_BIO) -> Result<Box<[u8]>, Error> {
            trace!(target: log_target!(), "Called");
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
                        trace!(target: log_target!(), "Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes => stopping for EOF");
                        break;
                    }
                    (0, _n) => {
                        warn!(target: log_target!(), "Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                    }
                    (1, 0) => {
                        warn!(target: log_target!(), "Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                    }
                    (1, _n) => {
                        trace!(target: log_target!(), "Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes => 👍");
                    }
                    (_r, _n) => {
                        error!(target: log_target!(), "Underlying upcall #{cnt:} to BIO_read_ex returned {ret:} after {bytes_read:} bytes");
                    }
                };
                if cnt > MAX_ITERATIONS {
                    error!(
                        target: log_target!(),
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

        #[expect(non_snake_case)]
        #[named]
        /// Makes a BIO_write_ex() core upcall.
        ///
        /// Refer to [BIO_write_ex(3ossl)](https://docs.openssl.org/3.2/man3/BIO_write/).
        fn BIO_write_ex(&self, bio: *mut OSSL_CORE_BIO, data: &[u8]) -> Result<usize, Error> {
            trace!(target: log_target!(), "Called");
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
    }

    pub trait CoreUpcallerWithCoreHandle: CoreUpcaller {
        fn get_core_handle(&self) -> *const OSSL_CORE_HANDLE;

        #[expect(non_snake_case)]
        #[named]
        /// Makes a core_obj_create() core upcall.
        ///
        /// Refer to [provider-base(7ossl)](https://docs.openssl.org/3.2/man7/provider-base/#core-functions)
        /// and [OBJ_create(3ossl)](https://docs.openssl.org/3.2/man3/OBJ_create/).
        fn OBJ_create(&self, oid: &CStr, sn: &CStr, ln: &CStr) -> Result<(), Error> {
            trace!(target: log_target!(), "Called");
            let handle = self.get_core_handle();

            static CELL: OnceLock<Option<unsafe extern "C" fn()>> = OnceLock::new();
            let fn_ptr = CELL.get_or_init(|| {
                let f = self.fn_from_core_dispatch(OSSL_FUNC_CORE_OBJ_CREATE);
                f
            });
            let fn_ptr = match fn_ptr {
                Some(f) => f,
                None => {
                    return Err(anyhow::anyhow!("No upcall pointer"));
                }
            };

            // FIXME: is there a way to just specify the type using the type alias OSSL_FUNC_core_obj_create_fn
            // instead of writing it all out again?
            let ffi_core_obj_create = unsafe {
                std::mem::transmute::<
                    *const (),
                    unsafe extern "C" fn(
                        prov: *const OSSL_CORE_HANDLE,
                        oid: *const c_char,
                        sn: *const c_char,
                        ln: *const c_char,
                    ) -> c_int,
                >(*fn_ptr as _)
            };

            let oid: *const c_char = oid.as_ptr();
            let sn: *const c_char = sn.as_ptr();
            let ln: *const c_char = ln.as_ptr();

            /// Refer to [provider-base(7ossl)](https://docs.openssl.org/3.2/man7/provider-base/#core-functions)
            const RET_SUCCESS: c_int = 1;
            const RET_FAILURE: c_int = 0;

            let ret = unsafe { ffi_core_obj_create(handle, oid, sn, ln) };
            match ret {
                RET_SUCCESS => Ok(()),
                RET_FAILURE => Err(anyhow!("core_obj_create() upcall failed")),
                _ => unreachable!(),
            }
        }

        #[expect(non_snake_case)]
        #[named]
        /// Makes a `core_obj_add_sigid()` core upcall.
        ///
        /// The `core_obj_add_sigid()` function registers a new composite signature
        /// algorithm (`sign_name`) consisting of an underlying signature algorithm
        /// (`pkey_name`) and digest algorithm (`digest_name`) for the given handle.
        ///
        /// It assumes that the OIDs for the composite signature algorithm as well
        /// as for the underlying signature and digest algorithms are either already
        /// known to OpenSSL or have been registered via a call to
        /// `core_obj_create()`.
        ///
        /// It corresponds to the OpenSSL function
        /// [`OBJ_add_sigid(3ossl)`](https://docs.openssl.org/3.2/man3/OBJ_add_sigid/),
        /// except that the objects are identified by name rather
        /// than a numeric NID.
        ///
        /// Any name (OID, short name or long name) can be used
        /// to identify the object.
        ///
        /// It will treat as success the case where the
        /// composite signature algorithm already exists (even if registered against
        /// a different underlying signature or digest algorithm).
        ///
        /// For `digest_name`, `NULL` or an empty string is permissible for
        /// signature algorithms that do not need a digest to operate correctly.
        /// The function returns 1 on success or 0 on failure.
        ///
        /// Refer to [provider-base(7ossl)](https://docs.openssl.org/3.2/man7/provider-base/#core-functions)
        /// and [OBJ_add_sigid(3ossl)](https://docs.openssl.org/3.2/man3/OBJ_add_sigid/).
        fn OBJ_add_sigid(
            &self,
            sign_name: &CStr,
            digest_name: Option<&CStr>,
            pkey_name: &CStr,
        ) -> Result<(), Error> {
            trace!(target: log_target!(), "Called");
            let handle = self.get_core_handle();

            static CELL: OnceLock<Option<unsafe extern "C" fn()>> = OnceLock::new();
            let fn_ptr = CELL.get_or_init(|| {
                let f = self.fn_from_core_dispatch(OSSL_FUNC_CORE_OBJ_ADD_SIGID);
                f
            });
            let fn_ptr = match fn_ptr {
                Some(f) => f,
                None => {
                    return Err(anyhow::anyhow!("No upcall pointer"));
                }
            };

            // FIXME: is there a way to just specify the type using the type alias OSSL_FUNC_core_obj_create_fn
            // instead of writing it all out again?
            let ffi_core_obj_add_sigid = unsafe {
                std::mem::transmute::<
                    *const (),
                    unsafe extern "C" fn(
                        prov: *const OSSL_CORE_HANDLE,
                        sign_name: *const c_char,
                        digest_name: *const c_char,
                        pkey_name: *const c_char,
                    ) -> c_int,
                >(*fn_ptr as _)
            };

            let sign_name: *const c_char = sign_name.as_ptr();
            let pkey_name: *const c_char = pkey_name.as_ptr();
            let digest_name: *const c_char = match digest_name {
                Some(s) => s.as_ptr(),
                None => core::ptr::null(),
            };

            /// Refer to [provider-base(7ossl)](https://docs.openssl.org/3.2/man7/provider-base/#core-functions)
            const RET_SUCCESS: c_int = 1;
            const RET_FAILURE: c_int = 0;

            let ret = unsafe { ffi_core_obj_add_sigid(handle, sign_name, digest_name, pkey_name) };
            match ret {
                RET_SUCCESS => Ok(()),
                RET_FAILURE => Err(anyhow!("core_obj_add_sigid() upcall failed")),
                _ => unreachable!(),
            }
        }
    }
}

use traits::*;

#[derive(Debug)]
pub struct CoreDispatch<'a> {
    _core_dispatch_slice: &'a [OSSL_DISPATCH],

    #[cfg(not(test))]
    core_dispatch_map: HashMap<u32, &'a OSSL_DISPATCH>,
}

impl<'a> TryFrom<*const OSSL_DISPATCH> for CoreDispatch<'a> {
    type Error = super::Error;

    #[cfg(not(test))]
    #[named]
    fn try_from(ptr: *const OSSL_DISPATCH) -> Result<Self, Self::Error> {
        const MAX_DISPATCH_SIZE: usize = 512;

        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut OSSL_DISPATCH> for &mut CoreDispatch<'a>"
        );

        // convert the upcall table to a slice for easier handling
        let core_dispatch_slice = if !ptr.is_null() {
            let mut i: usize = 0;
            loop {
                let f = unsafe { *ptr.offset(i as isize) };
                if f.function_id == OSSL_DISPATCH::END.function_id {
                    break;
                }
                if i >= MAX_DISPATCH_SIZE {
                    error!(target: log_target!(), "the core_dispatch table seems to be excessively long, bailing!");
                    return Err(anyhow::anyhow!(
                        "the core_dispatch table seems to be excessively long, bailing!"
                    ));
                }
                i += 1;
            }
            unsafe { std::slice::from_raw_parts(ptr, i) }
        } else {
            error!(target: log_target!(), "Got a null core_dispatch table");
            return Err(anyhow::anyhow!("Got a null core_dispatch table"));
        };

        let mut core_dispatch_map = HashMap::with_capacity(core_dispatch_slice.len());
        for entry in core_dispatch_slice {
            core_dispatch_map.insert(entry.function_id as u32, entry);
        }

        Ok(Self {
            _core_dispatch_slice: core_dispatch_slice,
            core_dispatch_map,
        })
    }

    #[cfg(test)]
    #[named]
    fn try_from(ptr: *const OSSL_DISPATCH) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut OSSL_DISPATCH> for &mut CoreDispatch<'a>"
        );

        if !ptr.is_null() {
            warn!(target: log_target!(), "This is a stub implementation for testing, it does not support upcalls");
        }

        let empty_slice = &[];
        return Ok(Self {
            _core_dispatch_slice: empty_slice,
        });
    }
}

impl<'a> CoreUpcaller for CoreDispatch<'a> {
    #[cfg(not(test))]
    #[named]
    fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()> {
        trace!(target: log_target!(), "Called");
        let f = self.core_dispatch_map.get(&id).map(|f| f.function);
        match f {
            Some(Some(f)) => Some(f),
            Some(None) => {
                error!(target: log_target!(), "core_dispatch entry for function_id {id:} was NULL");
                None
            }
            None => {
                warn!(target: log_target!(), "no entry in core_dispatch for function_id {id:}");
                None
            }
        }
    }

    #[cfg(test)]
    #[named]
    fn fn_from_core_dispatch(&self, _id: u32) -> Option<unsafe extern "C" fn()> {
        trace!(target: log_target!(), "Called");
        warn!(target: log_target!(), "This is the bogus test implementation");
        None
    }
}

#[derive(Debug)]
pub struct CoreDispatchWithCoreHandle<'a> {
    core_dispatch: CoreDispatch<'a>,
    core_handle: *const OSSL_CORE_HANDLE,
}

impl CoreUpcaller for CoreDispatchWithCoreHandle<'_> {
    fn fn_from_core_dispatch(&self, id: u32) -> Option<unsafe extern "C" fn()> {
        return self.core_dispatch.fn_from_core_dispatch(id);
    }
}

impl CoreUpcallerWithCoreHandle for CoreDispatchWithCoreHandle<'_> {
    fn get_core_handle(&self) -> *const OSSL_CORE_HANDLE {
        self.core_handle
    }
}

impl<'a> From<CoreDispatchWithCoreHandle<'a>> for CoreDispatch<'a> {
    fn from(value: CoreDispatchWithCoreHandle<'a>) -> Self {
        value.core_dispatch
    }
}

impl<'a> From<(CoreDispatch<'a>, *const OSSL_CORE_HANDLE)> for CoreDispatchWithCoreHandle<'a> {
    fn from(value: (CoreDispatch<'a>, *const OSSL_CORE_HANDLE)) -> Self {
        let (core_dispatch, core_handle) = value;
        Self {
            core_dispatch,
            core_handle,
        }
    }
}

impl<'a> From<CoreDispatchWithCoreHandle<'a>> for (CoreDispatch<'a>, *const OSSL_CORE_HANDLE) {
    fn from(value: CoreDispatchWithCoreHandle<'a>) -> Self {
        let core_handle = value.get_core_handle();
        let core_dispatch = value.into();

        (core_dispatch, core_handle)
    }
}

use super::*;
use anyhow::anyhow;
use bindings::{
    OSSL_CORE_BIO, OSSL_FUNC_BIO_READ_EX, OSSL_FUNC_BIO_WRITE_EX, OSSL_FUNC_CORE_OBJ_CREATE,
};
use std::ffi::{c_char, c_int, c_void, CStr};

impl<'a> OpenSSLProvider<'a> {
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

    #[allow(dead_code)]
    #[expect(non_snake_case)]
    /// Makes a core_obj_create() core upcall.
    ///
    /// Refer to [provider-base(7ossl)](https://docs.openssl.org/3.2/man7/provider-base/#core-functions)
    /// and [OBJ_create(3ossl)](https://docs.openssl.org/3.2/man3/OBJ_create/).
    pub(crate) fn OBJ_create(&self, oid: &CStr, sn: &CStr, ln: &CStr) -> Result<(), Error> {
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

        let handle = self.handle;
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
}

use crate::named;
use crate::OpenSSLProvider;
use libc::c_void;
use rust_openssl_core_provider::bindings;

use bindings::OSSL_ALGORITHM;
use bindings::OSSL_OP_KEM;
use bindings::OSSL_OP_KEYMGMT;

#[named]
pub extern "C" fn query_operation(
    vprovctx: *mut c_void,
    operation_id: i32,
    no_cache: *mut i32,
) -> *const OSSL_ALGORITHM {
    trace!(target: log_target!(), "{}", "Called!");

    let provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
    if !no_cache.is_null() {
        unsafe {
            *no_cache = 0;
        }
    }

    /* this is still wrong, when thinking we will have multiple adapters, but works for now */
    match operation_id as u32 {
        x if x == OSSL_OP_KEM => provctx.adapters_ctx.libcrux.get_op_kem(),
        x if x == OSSL_OP_KEYMGMT => provctx.adapters_ctx.libcrux.get_op_keymgmt(),
        unsupported_op_id => {
            trace!(target: log_target!(), "Unsupported operation_id: {}", unsupported_op_id);
            std::ptr::null()
        }
    }
}

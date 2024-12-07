use std::ffi::CStr;

use crate::named;
use crate::OpenSSLProvider;
use libc::{c_char, c_int, c_void};
use rust_openssl_core_provider::bindings;

use bindings::OSSL_ALGORITHM;
use bindings::OSSL_CALLBACK;
use bindings::OSSL_OP_KEM;
use bindings::OSSL_OP_KEYMGMT;
use bindings::{
    OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID, OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
    OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
    OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
    OSSL_CAPABILITY_TLS_GROUP_NAME, OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
};
use crate::osslparams::{IntData, OSSLParam, OSSLParamData, UIntData, Utf8StringData, OSSL_PARAM_END};

#[named]
pub(crate) extern "C" fn query_operation(
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

#[named]
pub(crate) extern "C" fn get_capabilities(
    vprovctx: *mut c_void,
    capability: *const c_char,
    cb: OSSL_CALLBACK,
    arg: *mut c_void,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
    let mut tls_group_params = vec![
        OSSLParam::Utf8String(Utf8StringData::new_null(OSSL_CAPABILITY_TLS_GROUP_NAME)),
        OSSLParam::Utf8String(Utf8StringData::new_null(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL)),
        OSSLParam::Utf8String(Utf8StringData::new_null(OSSL_CAPABILITY_TLS_GROUP_ALG)),
        OSSLParam::UInt(UIntData::new_null(OSSL_CAPABILITY_TLS_GROUP_ID)),
        OSSLParam::UInt(UIntData::new_null(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS)),
        OSSLParam::Int(IntData::new_null(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS)),
        OSSLParam::Int(IntData::new_null(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS)),
        OSSLParam::Int(IntData::new_null(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS)),
        OSSLParam::Int(IntData::new_null(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS)),
        OSSLParam::UInt(UIntData::new_null(OSSL_CAPABILITY_TLS_GROUP_IS_KEM)),
    ];
    // oqs-provider keeps these values in a struct in an array that seems to be generated at build
    // time and not actually committed into the repo in a readable format; I dug them up with gdb.
    // TODO: check return values? surely there's a better way to do this than all these `let _`s....
    let _ = tls_group_params[0].set(c"X25519MLKEM768"); // IANA group name
    let _ = tls_group_params[1].set(c"X25519MLKEM768"); // group name according to the provider
    let _ = tls_group_params[2].set(c"X25519MLKEM768"); // algorithm name
    let _ = tls_group_params[3].set(0x11ec as u32);     // group ID
    let _ = tls_group_params[4].set(192 as u32);        // number of bits of security
    let _ = tls_group_params[5].set(0x0304);            // min TLS: v1.3
    let _ = tls_group_params[6].set(0);                 // max TLS: no set version
    let _ = tls_group_params[7].set(-1);                // min DTLS (do not use this group at all with DTLS)
    let _ = tls_group_params[8].set(-1);                // max DTLS (do not use this group at all with DTLS)
    let _ = tls_group_params[9].set(1 as u32);          // is KEM: yes
    // TODO: eliminate code duplication between here and OpenSSLProvider::get_params_array
    let tls_group_params_boxed_slice = Box::new(
        tls_group_params
            .clone()
            .into_iter()
            .map(|p| (unsafe { *p.get_c_struct() }))
            .chain(std::iter::once(OSSL_PARAM_END))
            .collect::<Vec<_>>(),
    )
    .into_boxed_slice();
    if unsafe { CStr::from_ptr(capability) } == c"TLS-GROUP" {
        match cb {
            Some(cb_fn) => unsafe { cb_fn(tls_group_params_boxed_slice.as_ptr(), arg) },
            None => 1,
        }
    } else {
        1
    }
}

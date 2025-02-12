use std::ffi::CStr;

use crate::forge::bindings;
use crate::named;
use crate::OpenSSLProvider;
use libc::{c_char, c_int, c_void};

use crate::adapters::libcrux::SecP256r1MLKEM768;
use crate::adapters::libcrux::X25519MLKEM768;
use crate::adapters::libcrux_draft::X25519MLKEM768Draft00;
use crate::osslparams::{OSSLParam, OSSL_PARAM_END};
use bindings::{
    OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID,
    OSSL_CAPABILITY_TLS_GROUP_IS_KEM, OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
    OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
    OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, OSSL_CAPABILITY_TLS_GROUP_NAME,
    OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
};

#[named]
pub(crate) extern "C" fn query_operation(
    vprovctx: *mut c_void,
    operation_id: i32,
    no_cache: *mut i32,
) -> *const OSSL_ALGORITHM {
    trace!(target: log_target!(), "{}", "Called!");

    let provctx: &mut OpenSSLProvider<'_> = match vprovctx.try_into() {
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
    trace!(target: log_target!(), "{}", "Called!");

    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return 0;
        }
    };
    let tls_groups_params = vec![
        {
            use Group::capabilities::tls_group as C;
            use X25519MLKEM768 as Group;

            vec![
                // IANA group name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_NAME, C::GROUP_NAME),
                // group name according to the provider
                OSSLParam::new_const_utf8string(
                    OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                    C::GROUP_NAME_INTERNAL,
                ),
                // keymgmt algorithm name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, C::GROUP_ALG),
                // IANA group ID
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &C::IANA_GROUP_ID),
                // number of bits of security
                OSSLParam::new_const_uint(
                    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
                    &C::SECURITY_BITS,
                ),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &C::MIN_TLS),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &C::MAX_TLS),
                // min DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &C::MIN_DTLS),
                // max DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &C::MAX_DTLS),
                // is KEM
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &C::IS_KEM),
                // IMPORTANT: always terminate a params array!!!
                OSSL_PARAM_END,
            ]
        },
        {
            use Group::capabilities::tls_group as C;
            use SecP256r1MLKEM768 as Group;

            vec![
                // IANA group name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_NAME, C::GROUP_NAME),
                // group name according to the provider
                OSSLParam::new_const_utf8string(
                    OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                    C::GROUP_NAME_INTERNAL,
                ),
                // keymgmt algorithm name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, C::GROUP_ALG),
                // IANA group ID
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &C::IANA_GROUP_ID),
                // number of bits of security
                OSSLParam::new_const_uint(
                    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
                    &C::SECURITY_BITS,
                ),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &C::MIN_TLS),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &C::MAX_TLS),
                // min DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &C::MIN_DTLS),
                // max DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &C::MAX_DTLS),
                // is KEM
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &C::IS_KEM),
                // IMPORTANT: always terminate a params array!!!
                OSSL_PARAM_END,
            ]
        },
        {
            use Group::capabilities::tls_group as C;
            use X25519MLKEM768Draft00 as Group;

            vec![
                // IANA group name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_NAME, C::GROUP_NAME),
                // group name according to the provider
                OSSLParam::new_const_utf8string(
                    OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                    C::GROUP_NAME_INTERNAL,
                ),
                // keymgmt algorithm name
                OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, C::GROUP_ALG),
                // IANA group ID
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &C::IANA_GROUP_ID),
                // number of bits of security
                OSSLParam::new_const_uint(
                    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
                    &C::SECURITY_BITS,
                ),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &C::MIN_TLS),
                // min TLS version
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &C::MAX_TLS),
                // min DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &C::MIN_DTLS),
                // max DTLS
                OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &C::MAX_DTLS),
                // is KEM
                OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &C::IS_KEM),
                // IMPORTANT: always terminate a params array!!!
                OSSL_PARAM_END,
            ]
        },
    ];

    // TODO: eliminate code duplication between here and OpenSSLProvider::get_params_array
    let tls_group_params_boxed_slices = tls_groups_params.into_boxed_slice();
    if unsafe { CStr::from_ptr(capability) } == c"TLS-GROUP" {
        match cb {
            Some(cb_fn) => {
                for slice in tls_group_params_boxed_slices {
                    trace!(target: log_target!(), "Current slice is {:?}", &slice);
                    let slicep = slice.as_ptr();
                    trace!(target: log_target!(), "Calling cb({:0x?}, {:0x?})", &slicep, arg);
                    let ret = unsafe { cb_fn(slicep, arg) };
                    trace!(target: log_target!(), "cb({:0x?}, {:0x?}) returned {:?}", &slicep, arg, ret);
                    if ret == 0 {
                        trace!(target: log_target!(), "Returning 0");
                        return 0;
                    }
                }
                trace!(target: log_target!(), "Iterated over all groups. Returning 1");
                return 1;
            }
            None => 1,
        }
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use crate::adapters::libcrux::SecP256r1MLKEM768::capabilities::tls_group::MIN_TLS;

    use super::*;

    #[test]
    fn test_query_usage() {
        use crate::bindings::{
            OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID,
            OSSL_CAPABILITY_TLS_GROUP_IS_KEM, OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
            OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
            OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, OSSL_CAPABILITY_TLS_GROUP_NAME,
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
        };

        use crate::adapters::libcrux::X25519MLKEM768 as Group;
        use Group::capabilities::tls_group as C;

        let v = vec![
            // IANA group name
            OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_NAME, C::GROUP_NAME),
            // group name according to the provider
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                C::GROUP_NAME_INTERNAL,
            ),
            // keymgmt algorithm name
            OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, C::GROUP_ALG),
            // IANA group ID
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &C::IANA_GROUP_ID),
            // number of bits of security
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &C::SECURITY_BITS),
            // min TLS version: v1.3
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &C::MIN_TLS),
            // min TLS version: no set version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &C::MAX_TLS),
            // min DTLS (do not use this group at all with DTLS)
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &C::MIN_DTLS),
            // max DTLS (do not use this group at all with DTLS)
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &C::MAX_DTLS),
            // is KEM: yes
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &C::IS_KEM),
            // IMPORTANT: always terminate a params array!!!
            OSSL_PARAM_END,
        ];

        let first = std::ptr::from_ref(v.first().unwrap());
        let params = OSSLParam::try_from(first).unwrap();

        for p in params {
            println!("{p:?}");
            assert_ne!(p.get_data_type(), None);
        }
    }
}

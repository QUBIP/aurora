use super::*;
use bindings::{dispatch_table_entry, OSSL_DISPATCH};
use bindings::{OSSL_FUNC_kem_decapsulate_fn, OSSL_FUNC_KEM_DECAPSULATE};
use bindings::{OSSL_FUNC_kem_decapsulate_init_fn, OSSL_FUNC_KEM_DECAPSULATE_INIT};
use bindings::{OSSL_FUNC_kem_encapsulate_fn, OSSL_FUNC_KEM_ENCAPSULATE};
use bindings::{OSSL_FUNC_kem_encapsulate_init_fn, OSSL_FUNC_KEM_ENCAPSULATE_INIT};
use bindings::{OSSL_FUNC_kem_freectx_fn, OSSL_FUNC_KEM_FREECTX};
use bindings::{OSSL_FUNC_kem_newctx_fn, OSSL_FUNC_KEM_NEWCTX};
use bindings::{OSSL_FUNC_keymgmt_export_fn, OSSL_FUNC_KEYMGMT_EXPORT};
use bindings::{OSSL_FUNC_keymgmt_export_types_ex_fn, OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX};
use bindings::{OSSL_FUNC_keymgmt_free_fn, OSSL_FUNC_KEYMGMT_FREE};
use bindings::{OSSL_FUNC_keymgmt_gen_cleanup_fn, OSSL_FUNC_KEYMGMT_GEN_CLEANUP};
use bindings::{OSSL_FUNC_keymgmt_gen_fn, OSSL_FUNC_KEYMGMT_GEN};
use bindings::{OSSL_FUNC_keymgmt_gen_init_fn, OSSL_FUNC_KEYMGMT_GEN_INIT};
use bindings::{OSSL_FUNC_keymgmt_gen_set_params_fn, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_gen_settable_params_fn, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_get_params_fn, OSSL_FUNC_KEYMGMT_GET_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_gettable_params_fn, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_has_fn, OSSL_FUNC_KEYMGMT_HAS};
use bindings::{OSSL_FUNC_keymgmt_import_fn, OSSL_FUNC_KEYMGMT_IMPORT};
use bindings::{OSSL_FUNC_keymgmt_import_types_ex_fn, OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX};
use bindings::{OSSL_FUNC_keymgmt_new_fn, OSSL_FUNC_KEYMGMT_NEW};
use bindings::{OSSL_FUNC_keymgmt_set_params_fn, OSSL_FUNC_KEYMGMT_SET_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_settable_params_fn, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS};

mod kem_functions;
mod keymgmt_functions;

pub(crate) type OurError = anyhow::Error;
pub(crate) use anyhow::anyhow;

// Ensure proper null-terminated C string
// https://docs.openssl.org/master/man7/provider/#algorithm-naming
pub(super) const NAMES: &CStr = c"SecP256r1MLKEM768";

/// NAME should be a substring of NAMES
pub(crate) const NAME: &CStr = c"SecP256r1MLKEM768";

// Ensure proper null-terminated C string
pub(super) const DESCRIPTION: &CStr = c"SecP256r1MLKEM768 from libcrux using NISEC combiner";

/// number of bits of security
pub(crate) const SECURITY_BITS: u32 = 192;

pub(crate) mod capabilities {
    use super::CStr;

    pub(crate) mod tls_group {
        use super::*;

        /// The name of the group as given in the
        /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
        pub(crate) const IANA_GROUP_NAME: &CStr = c"SecP256r1MLKEM768";

        /// The TLS group id value as given in the
        /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
        pub(crate) const IANA_GROUP_ID: u32 = 4587;

        /// An alias for `IANA_GROUP_NAME`
        pub(crate) use self::IANA_GROUP_NAME as GROUP_NAME;

        /// group name according to this provider
        pub(crate) use super::super::NAME as GROUP_NAME_INTERNAL;

        /// keymgmt algorithm name
        pub(crate) use super::super::NAME as GROUP_ALG;

        /// min TLS: v1.3
        pub(crate) const MIN_TLS: i32 = 0x0304;
        /// max TLS: no set version
        pub(crate) const MAX_TLS: i32 = 0;
        /// min DTLS (do not use this group at all with DTLS)
        pub(crate) const MIN_DTLS: i32 = -1;
        /// max DTLS (do not use this group at all with DTLS)
        pub(crate) const MAX_DTLS: i32 = -1;
        /// is KEM: yes
        pub(crate) const IS_KEM: u32 = 1;

        /// number of bits of security
        pub(crate) use super::super::SECURITY_BITS;

        use crate::bindings::{
            OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID,
            OSSL_CAPABILITY_TLS_GROUP_IS_KEM, OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
            OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
            OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, OSSL_CAPABILITY_TLS_GROUP_NAME,
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
        };
        use openssl_provider_forge::osslparams;
        use osslparams::{OSSLParam, CONST_OSSL_PARAM};

        pub(crate) static OSSL_PARAM_ARRAY: &[CONST_OSSL_PARAM] = &[
            // IANA group name
            OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_NAME, GROUP_NAME),
            // group name according to the provider
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                GROUP_NAME_INTERNAL,
            ),
            // keymgmt algorithm name
            OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, GROUP_ALG),
            // IANA group ID
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &IANA_GROUP_ID),
            // number of bits of security
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &SECURITY_BITS),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &MIN_TLS),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &MAX_TLS),
            // min DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &MIN_DTLS),
            // max DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &MAX_DTLS),
            // is KEM
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &IS_KEM),
            // IMPORTANT: always terminate a params array!!!
            CONST_OSSL_PARAM::END,
        ];
    }
}

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/master/man7/provider-kem/
pub(super) const KEM_FUNCTIONS: [OSSL_DISPATCH; 7] = [
    dispatch_table_entry!(
        OSSL_FUNC_KEM_NEWCTX,
        OSSL_FUNC_kem_newctx_fn,
        kem_functions::newctx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_FREECTX,
        OSSL_FUNC_kem_freectx_fn,
        kem_functions::freectx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        OSSL_FUNC_kem_encapsulate_init_fn,
        kem_functions::encapsulate_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_ENCAPSULATE,
        OSSL_FUNC_kem_encapsulate_fn,
        kem_functions::encapsulate
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_DECAPSULATE_INIT,
        OSSL_FUNC_kem_decapsulate_init_fn,
        kem_functions::decapsulate_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEM_DECAPSULATE,
        OSSL_FUNC_kem_decapsulate_fn,
        kem_functions::decapsulate
    ),
    OSSL_DISPATCH::END,
];

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/master/man7/provider-keymgmt/
pub(super) const KMGMT_FUNCTIONS: [OSSL_DISPATCH; 17] = [
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_NEW,
        OSSL_FUNC_keymgmt_new_fn,
        keymgmt_functions::new
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_FREE,
        OSSL_FUNC_keymgmt_free_fn,
        keymgmt_functions::free
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_HAS,
        OSSL_FUNC_keymgmt_has_fn,
        keymgmt_functions::has
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN,
        OSSL_FUNC_keymgmt_gen_fn,
        keymgmt_functions::gen
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        OSSL_FUNC_keymgmt_gen_cleanup_fn,
        keymgmt_functions::gen_cleanup
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_INIT,
        OSSL_FUNC_keymgmt_gen_init_fn,
        keymgmt_functions::gen_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        OSSL_FUNC_keymgmt_gen_set_params_fn,
        keymgmt_functions::gen_set_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        OSSL_FUNC_keymgmt_gen_settable_params_fn,
        keymgmt_functions::gen_settable_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GET_PARAMS,
        OSSL_FUNC_keymgmt_get_params_fn,
        keymgmt_functions::get_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        OSSL_FUNC_keymgmt_gettable_params_fn,
        keymgmt_functions::gettable_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_SET_PARAMS,
        OSSL_FUNC_keymgmt_set_params_fn,
        keymgmt_functions::set_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        OSSL_FUNC_keymgmt_settable_params_fn,
        keymgmt_functions::settable_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT,
        OSSL_FUNC_keymgmt_import_fn,
        keymgmt_functions::import
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT,
        OSSL_FUNC_keymgmt_export_fn,
        keymgmt_functions::export
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX,
        OSSL_FUNC_keymgmt_import_types_ex_fn,
        keymgmt_functions::import_types_ex
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX,
        OSSL_FUNC_keymgmt_export_types_ex_fn,
        keymgmt_functions::export_types_ex
    ),
    OSSL_DISPATCH::END,
];

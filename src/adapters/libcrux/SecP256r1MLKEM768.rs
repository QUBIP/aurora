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
    pub(crate) mod tls_group {
        use super::super::forge;
        use forge::capabilities::tls_group;
        use forge::osslparams::CONST_OSSL_PARAM;
        use tls_group::*;

        pub(crate) struct TLSGroupCap;

        impl TLSGroup for TLSGroupCap {
            /// The name of the group as given in the
            /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
            const IANA_GROUP_NAME: &CStr = c"SecP256r1MLKEM768";

            /// The TLS group id value as given in the
            /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
            const IANA_GROUP_ID: u32 = 4587;

            /// group name according to this provider
            const GROUP_NAME_INTERNAL: &CStr = super::super::NAME;

            /// keymgmt algorithm name
            const GROUP_ALG: &CStr = Self::GROUP_NAME_INTERNAL;

            /// number of bits of security
            const SECURITY_BITS: u32 = super::super::SECURITY_BITS;

            /// min TLS: v1.3
            const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
            /// max TLS: no set version
            const MAX_TLS: TLSVersion = TLSVersion::None;
            /// min DTLS (do not use this group at all with DTLS)
            const MIN_DTLS: DTLSVersion = DTLSVersion::Disabled;
            /// max DTLS (do not use this group at all with DTLS)
            const MAX_DTLS: DTLSVersion = DTLSVersion::Disabled;

            const IS_KEM: bool = true;
        }

        pub(crate) static OSSL_PARAM_ARRAY: &[CONST_OSSL_PARAM] =
            tls_group::as_params!(TLSGroupCap);
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

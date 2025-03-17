#![expect(dead_code)]

use super::*;
use bindings::{dispatch_table_entry, OSSL_DISPATCH};
use bindings::{OSSL_FUNC_decoder_decode_fn, OSSL_FUNC_DECODER_DECODE};
use bindings::{OSSL_FUNC_decoder_does_selection_fn, OSSL_FUNC_DECODER_DOES_SELECTION};
use bindings::{OSSL_FUNC_decoder_export_object_fn, OSSL_FUNC_DECODER_EXPORT_OBJECT};
use bindings::{OSSL_FUNC_decoder_freectx_fn, OSSL_FUNC_DECODER_FREECTX};
use bindings::{OSSL_FUNC_decoder_get_params_fn, OSSL_FUNC_DECODER_GET_PARAMS};
use bindings::{OSSL_FUNC_decoder_gettable_params_fn, OSSL_FUNC_DECODER_GETTABLE_PARAMS};
use bindings::{OSSL_FUNC_decoder_newctx_fn, OSSL_FUNC_DECODER_NEWCTX};
use bindings::{OSSL_FUNC_decoder_set_ctx_params_fn, OSSL_FUNC_DECODER_SET_CTX_PARAMS};
use bindings::{OSSL_FUNC_decoder_settable_ctx_params_fn, OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS};
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
use bindings::{OSSL_FUNC_signature_freectx_fn, OSSL_FUNC_SIGNATURE_FREECTX};
use bindings::{OSSL_FUNC_signature_newctx_fn, OSSL_FUNC_SIGNATURE_NEWCTX};
use bindings::{OSSL_FUNC_signature_sign_fn, OSSL_FUNC_SIGNATURE_SIGN};
use bindings::{OSSL_FUNC_signature_sign_init_fn, OSSL_FUNC_SIGNATURE_SIGN_INIT};
use bindings::{OSSL_FUNC_signature_verify_fn, OSSL_FUNC_SIGNATURE_VERIFY};
use bindings::{OSSL_FUNC_signature_verify_init_fn, OSSL_FUNC_SIGNATURE_VERIFY_INIT};

mod decoder_functions;
mod keymgmt_functions;
mod signature_functions;

pub(crate) type OurError = anyhow::Error;
pub(crate) use anyhow::anyhow;

// Ensure proper null-terminated C string
// https://docs.openssl.org/master/man7/provider/#algorithm-naming
pub(super) const NAMES: &CStr = c"ML-DSA-65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65:mldsa65";

/// NAME should be a substring of NAMES
pub(crate) const NAME: &CStr = c"ML-DSA-65";

// Ensure proper null-terminated C string
pub(super) const DESCRIPTION: &CStr = c"ML-DSA-65 from pqclean";

/// number of bits of security
pub(crate) const SECURITY_BITS: u32 = 192;

pub(crate) mod capabilities {
    pub(crate) mod tls_sigalg {
        use super::super::forge;
        use forge::capabilities::tls_sigalg;
        use forge::osslparams::CONST_OSSL_PARAM;
        use tls_sigalg::*;

        /// A [_unit-like struct_][rustbook:unit-like-structs] implementing [`TLSSigAlg`] for `id-ml-dsa-65`.
        ///
        /// [rustbook:unit-like-structs]: https://doc.rust-lang.org/book/ch05-01-defining-structs.html#unit-like-structs-without-any-fields
        pub(crate) struct TLSSigAlgCap;

        /// Implement [`TLSSigAlg`] for [`TLSSigAlgCap`]
        ///
        /// # NOTE
        ///
        /// > For ML-DSA we currently refer to ids reserved by <https://datatracker.ietf.org/doc/draft-tls-westerbaan-mldsa/>
        /// > as IANA does not list ML-DSA in the registry yet.
        /// > These values match the [values used in OpenSSL 3.5 in `providers/common/capabilities.c`](https://github.com/openssl/openssl/blob/97fbbc2f1f023d712d38263c824b6c5c8ffe6e61/providers/common/capabilities.c#L316-L320)
        ///
        /// We use default values for MAX_TLS (none), MIN_DTLS (disabled), MAX_DTLS (disabled)
        impl TLSSigAlg for TLSSigAlgCap {
            /// The name of the signature algorithm as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme] as "Description".
            ///
            /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
            ///
            /// # NOTE
            ///
            /// > For ML-DSA we currently refer to ids reserved by <https://datatracker.ietf.org/doc/draft-tls-westerbaan-mldsa/>
            /// > as IANA does not list ML-DSA in the registry yet.
            /// > These values match the [values used in OpenSSL 3.5 in `providers/common/capabilities.c`](https://github.com/openssl/openssl/blob/97fbbc2f1f023d712d38263c824b6c5c8ffe6e61/providers/common/capabilities.c#L316-L320)
            const SIGALG_IANA_NAME: &CStr = c"mldsa65";

            /// The TLS algorithm ID value as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme].
            ///
            /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
            ///
            /// # NOTE
            ///
            /// > For ML-DSA we currently refer to ids reserved by <https://datatracker.ietf.org/doc/draft-tls-westerbaan-mldsa/>
            /// > as IANA does not list ML-DSA in the registry yet.
            /// > These values match the [values used in OpenSSL 3.5 in `providers/common/capabilities.c`](https://github.com/openssl/openssl/blob/97fbbc2f1f023d712d38263c824b6c5c8ffe6e61/providers/common/capabilities.c#L316-L320)
            const SIGALG_CODEPOINT: u32 = 0x0905; // 2309 in decimal notation

            /// A name for the signature algorithm as known by the provider.
            ///
            /// Note this is also the name that
            /// [`SSL_CONF_cmd(-sigalgs)`][SSL_CONF_cmd(3ossl):cli]/[`SSL_CONF_cmd(SignatureAlgorithms)`][SSL_CONF_cmd(3ossl):conf]
            /// will support.
            ///
            /// [SSL_CONF_cmd(3ossl):cli]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-command-line-commands
            /// [SSL_CONF_cmd(3ossl):conf]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-configuration-file-commands
            const SIGALG_NAME: &CStr = c"ML-DSA-65";

            /// The OID of the [`Self::SIGALG_SIG_NAME`] algorithm in canonical numeric text form. \[optional\]
            ///
            /// # NOTE
            ///
            /// > The OIDs for ML-DSA come from the [NIST Computer Security Objects Register](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration).
            ///
            /// > These values match the [values used in OpenSSL 3.5 in `providers/common/capabilities.c`](https://github.com/openssl/openssl/blob/97fbbc2f1f023d712d38263c824b6c5c8ffe6e61/providers/common/capabilities.c#L316-L320)
            const SIGALG_OID: Option<&CStr> = Some(c"2.16.840.1.101.3.4.3.18");

            const SECURITY_BITS: u32 = super::super::SECURITY_BITS;

            /// min TLS: v1.3
            const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
            // use default values for MAX_TLS (none), MIN_DTLS (disabled), MAX_DTLS (disabled) (see doc-comment)
        }

        pub(crate) static OSSL_PARAM_ARRAY: &[CONST_OSSL_PARAM] =
            tls_sigalg::as_params!(TLSSigAlgCap);

        pub(crate) struct OQScompatCap;

        /// Implement [`TLSSigAlg`] for [`OQScompatCap`].
        ///
        /// This is identical to [`TLSSigAlgCap`], but uses `"mldsa65"` for [`TLSSigAlg::SIGALG_NAME`] for compatiblity with the OQS provider.
        impl TLSSigAlg for OQScompatCap {
            /// A name for the signature algorithm as known by the provider.
            ///
            /// Note this is also the name that
            /// [`SSL_CONF_cmd(-sigalgs)`][SSL_CONF_cmd(3ossl):cli]/[`SSL_CONF_cmd(SignatureAlgorithms)`][SSL_CONF_cmd(3ossl):conf]
            /// will support.
            ///
            /// Here we use `"mldsa65"` for compatiblity with the OQS provider.
            ///
            /// [SSL_CONF_cmd(3ossl):cli]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-command-line-commands
            /// [SSL_CONF_cmd(3ossl):conf]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-configuration-file-commands
            const SIGALG_NAME: &CStr = c"mldsa65";

            const SIGALG_IANA_NAME: &CStr = TLSSigAlgCap::SIGALG_IANA_NAME;
            const SIGALG_CODEPOINT: u32 = TLSSigAlgCap::SIGALG_CODEPOINT;
            const SECURITY_BITS: u32 = TLSSigAlgCap::SECURITY_BITS;

            /// If needed, this OID has already been defined
            const SIGALG_OID: Option<&CStr> = None;
            /// If needed, this OID has already been defined
            const SIGALG_SIG_OID: Option<&CStr> = None;
            /// If needed, this OID has already been defined
            const SIGALG_HASH_OID: Option<&CStr> = None;
            /// If needed, this OID has already been defined
            const SIGALG_KEYTYPE_OID: Option<&CStr> = None;

            const SIGALG_SIG_NAME: Option<&CStr> = TLSSigAlgCap::SIGALG_SIG_NAME;
            const SIGALG_HASH_NAME: Option<&CStr> = TLSSigAlgCap::SIGALG_HASH_NAME;
            const SIGALG_KEYTYPE: Option<&CStr> = TLSSigAlgCap::SIGALG_KEYTYPE;
            const MIN_TLS: TLSVersion = TLSSigAlgCap::MIN_TLS;
            const MAX_TLS: TLSVersion = TLSSigAlgCap::MAX_TLS;
            const MIN_DTLS: DTLSVersion = TLSSigAlgCap::MIN_DTLS;
            const MAX_DTLS: DTLSVersion = TLSSigAlgCap::MAX_DTLS;
        }

        pub(crate) static OSSL_PARAM_ARRAY_OQSCOMP: &[CONST_OSSL_PARAM] =
            tls_sigalg::as_params!(OQScompatCap);
    }
}

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/3.2/man7/provider-signature/
pub(super) const SIG_FUNCTIONS: [OSSL_DISPATCH; 7] = [
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_NEWCTX,
        OSSL_FUNC_signature_newctx_fn,
        signature_functions::newctx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_FREECTX,
        OSSL_FUNC_signature_freectx_fn,
        signature_functions::freectx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SIGN_INIT,
        OSSL_FUNC_signature_sign_init_fn,
        signature_functions::sign_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SIGN,
        OSSL_FUNC_signature_sign_fn,
        signature_functions::sign
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        OSSL_FUNC_signature_verify_init_fn,
        signature_functions::verify_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_VERIFY,
        OSSL_FUNC_signature_verify_fn,
        signature_functions::verify
    ),
    OSSL_DISPATCH::END,
];

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/3.2/man7/provider-keymgmt/
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

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/3.2/man7/provider-decoder/
pub(super) const DECODER_FUNCTIONS: [OSSL_DISPATCH; 10] = [
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_GET_PARAMS,
        OSSL_FUNC_decoder_get_params_fn,
        decoder_functions::get_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_GETTABLE_PARAMS,
        OSSL_FUNC_decoder_gettable_params_fn,
        decoder_functions::gettable_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_NEWCTX,
        OSSL_FUNC_decoder_newctx_fn,
        decoder_functions::newctx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_FREECTX,
        OSSL_FUNC_decoder_freectx_fn,
        decoder_functions::freectx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        OSSL_FUNC_decoder_set_ctx_params_fn,
        decoder_functions::set_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        OSSL_FUNC_decoder_settable_ctx_params_fn,
        decoder_functions::settable_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_DOES_SELECTION,
        OSSL_FUNC_decoder_does_selection_fn,
        decoder_functions::does_selection
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_DECODE,
        OSSL_FUNC_decoder_decode_fn,
        decoder_functions::decode
    ),
    dispatch_table_entry!(
        OSSL_FUNC_DECODER_EXPORT_OBJECT,
        OSSL_FUNC_decoder_export_object_fn,
        decoder_functions::export_object
    ),
    OSSL_DISPATCH::END,
];

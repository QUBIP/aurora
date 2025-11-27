#![expect(dead_code)]
#![expect(unused_imports)]

use super::*;
use bindings::{dispatch_table_entry, OSSL_DISPATCH};
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
use bindings::{OSSL_FUNC_keymgmt_load_fn, OSSL_FUNC_KEYMGMT_LOAD};
use bindings::{OSSL_FUNC_keymgmt_match_fn, OSSL_FUNC_KEYMGMT_MATCH};
use bindings::{OSSL_FUNC_keymgmt_new_fn, OSSL_FUNC_KEYMGMT_NEW};
use bindings::{OSSL_FUNC_keymgmt_set_params_fn, OSSL_FUNC_KEYMGMT_SET_PARAMS};
use bindings::{OSSL_FUNC_keymgmt_settable_params_fn, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS};
use bindings::{OSSL_FUNC_signature_digest_sign_fn, OSSL_FUNC_SIGNATURE_DIGEST_SIGN};
use bindings::{OSSL_FUNC_signature_digest_sign_init_fn, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT};
use bindings::{OSSL_FUNC_signature_digest_verify_fn, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY};
use bindings::{OSSL_FUNC_signature_digest_verify_init_fn, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT};
use bindings::{OSSL_FUNC_signature_freectx_fn, OSSL_FUNC_SIGNATURE_FREECTX};
use bindings::{OSSL_FUNC_signature_get_ctx_params_fn, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS};
use bindings::{
    OSSL_FUNC_signature_gettable_ctx_params_fn, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
};
use bindings::{OSSL_FUNC_signature_newctx_fn, OSSL_FUNC_SIGNATURE_NEWCTX};
use bindings::{OSSL_FUNC_signature_set_ctx_params_fn, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS};
use bindings::{
    OSSL_FUNC_signature_settable_ctx_params_fn, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
};
use bindings::{OSSL_FUNC_signature_sign_fn, OSSL_FUNC_SIGNATURE_SIGN};
use bindings::{OSSL_FUNC_signature_sign_init_fn, OSSL_FUNC_SIGNATURE_SIGN_INIT};
use bindings::{OSSL_FUNC_signature_verify_fn, OSSL_FUNC_SIGNATURE_VERIFY};
use bindings::{OSSL_FUNC_signature_verify_init_fn, OSSL_FUNC_SIGNATURE_VERIFY_INIT};

mod decoder_functions;
mod encoder_functions;
mod keymgmt_functions;

#[path = "../common/signature.rs"]
mod signature;

#[path = "../common/signature_functions.rs"]
mod signature_functions;

pub(crate) type OurError = anyhow::Error;
pub(crate) use anyhow::anyhow;

// Ensure proper null-terminated C string
// https://docs.openssl.org/master/man7/provider/#algorithm-naming
pub(super) const NAMES: &CStr = c"ML-DSA-44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44:mldsa44";

/// NAME should be a substring of NAMES
pub(crate) const NAME: &CStr = c"ML-DSA-44";

/// LONG_NAME should be a substring of NAMES
pub(crate) const LONG_NAME: &CStr = c"id-ml-dsa-44";

/// OID should be a substring of NAMES
///
/// This OID is defined in
/// <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>.
pub(crate) const OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 17);
pub(crate) const OID_PKCS8: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
pub(crate) const SIGALG_OID: Option<&CStr> = Some(c"2.16.840.1.101.3.4.3.17");

crate::adapters::common::keymgmt_functions::oid_consistency_tests!();

/// [RFC 5280 AlgorithmIdentifier](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2)
/// in DER-encoded format.
use std::sync::LazyLock;
pub(crate) static ALGORITHM_ID_DER: LazyLock<Vec<u8>> = LazyLock::new(|| {
    asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            w.write_element(&OID)?;
            Ok(())
        }))
    })
    .expect("OID should be encodable as AlgorithmIdentifier")
});

// Ensure proper null-terminated C string
pub(super) const DESCRIPTION: &CStr = c"ML-DSA-44 from pqclean";

/// number of bits of security
pub(crate) const SECURITY_BITS: u32 = 128;

/// used to register an Signature Id Object within OpenSSL
/// for this algorithm
pub(crate) const OBJ_SIGID: ObjSigId = ObjSigId {
    oid: SIGALG_OID.unwrap(),
    short_name: NAME,
    long_name: LONG_NAME,
    digest_name: None,
};

#[allow(unused_imports)]
pub(crate) use keymgmt_functions::{PUBKEY_LEN, SECRETKEY_LEN, SIGNATURE_LEN};

pub(crate) mod capabilities {
    pub(crate) mod tls_sigalg {
        use super::super::forge;
        use forge::capabilities::tls_sigalg;
        use forge::osslparams::CONST_OSSL_PARAM;
        use tls_sigalg::*;

        /// A [_unit-like struct_][rustbook:unit-like-structs] implementing [`TLSSigAlg`] for `id-ml-dsa-44`.
        ///
        /// [rustbook:unit-like-structs]: https://doc.rust-lang.org/book/ch05-01-defining-structs.html#unit-like-structs-without-any-fields
        pub(crate) struct TLSSigAlgCap;

        /// Implement [`TLSSigAlg`] for [`TLSSigAlgCap`]
        ///
        /// # NOTE
        ///
        /// > For ML-DSA we refer to ids reserved by <https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-01#name-ml-dsa-signaturescheme-valu>.
        ///
        /// We use default values for MAX_TLS (none), MIN_DTLS (disabled), MAX_DTLS (disabled)
        impl TLSSigAlg for TLSSigAlgCap {
            /// The name of the signature algorithm as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme] as "Description".
            ///
            /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
            ///
            /// # NOTE
            ///
            /// > For ML-DSA we refer to ids reserved by <https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-01#name-ml-dsa-signaturescheme-valu>.
            const SIGALG_IANA_NAME: &CStr = c"mldsa44";

            /// The TLS algorithm ID value as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme].
            ///
            /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
            ///
            /// # NOTE
            ///
            /// > For ML-DSA we refer to ids reserved by <https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-01#name-ml-dsa-signaturescheme-valu>.
            const SIGALG_CODEPOINT: u32 = 0x0904; // 2308 in decimal notation

            /// A name for the signature algorithm as known by the provider.
            ///
            /// Note this is also the name that
            /// [`SSL_CONF_cmd(-sigalgs)`][SSL_CONF_cmd(3ossl):cli]/[`SSL_CONF_cmd(SignatureAlgorithms)`][SSL_CONF_cmd(3ossl):conf]
            /// will support.
            ///
            /// [SSL_CONF_cmd(3ossl):cli]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-command-line-commands
            /// [SSL_CONF_cmd(3ossl):conf]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-configuration-file-commands
            const SIGALG_NAME: &CStr = c"ML-DSA-44";

            /// The OID of the [`Self::SIGALG_SIG_NAME`] algorithm in canonical numeric text form. \[optional\]
            ///
            /// # NOTE
            ///
            /// > The OIDs for ML-DSA come from the [NIST Computer Security Objects Register](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration).
            ///
            /// > These values match the [values used in OpenSSL 3.5 in `providers/common/capabilities.c`](https://github.com/openssl/openssl/blob/97fbbc2f1f023d712d38263c824b6c5c8ffe6e61/providers/common/capabilities.c#L316-L320)
            const SIGALG_OID: Option<&CStr> = super::super::SIGALG_OID;

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
        /// This is identical to [`TLSSigAlgCap`], but uses `"mldsa44"` for [`TLSSigAlg::SIGALG_NAME`] for compatiblity with the OQS provider.
        impl TLSSigAlg for OQScompatCap {
            /// A name for the signature algorithm as known by the provider.
            ///
            /// Note this is also the name that
            /// [`SSL_CONF_cmd(-sigalgs)`][SSL_CONF_cmd(3ossl):cli]/[`SSL_CONF_cmd(SignatureAlgorithms)`][SSL_CONF_cmd(3ossl):conf]
            /// will support.
            ///
            /// Here we use `"mldsa44"` for compatiblity with the OQS provider.
            ///
            /// [SSL_CONF_cmd(3ossl):cli]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-command-line-commands
            /// [SSL_CONF_cmd(3ossl):conf]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-configuration-file-commands
            const SIGALG_NAME: &CStr = c"mldsa44";

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
pub(super) const SIG_FUNCTIONS: &[OSSL_DISPATCH] = &[
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
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SIGN_INIT,
        OSSL_FUNC_signature_sign_init_fn,
        signature_functions::sign_init
    ),
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SIGN,
        OSSL_FUNC_signature_sign_fn,
        signature_functions::sign
    ),
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        OSSL_FUNC_signature_verify_init_fn,
        signature_functions::verify_init
    ),
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_VERIFY,
        OSSL_FUNC_signature_verify_fn,
        signature_functions::verify
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        OSSL_FUNC_signature_digest_verify_init_fn,
        signature_functions::digest_verify_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        OSSL_FUNC_signature_digest_verify_fn,
        signature_functions::digest_verify
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        OSSL_FUNC_signature_digest_sign_init_fn,
        signature_functions::digest_sign_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        OSSL_FUNC_signature_digest_sign_fn,
        signature_functions::digest_sign
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        OSSL_FUNC_signature_gettable_ctx_params_fn,
        signature_functions::gettable_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        OSSL_FUNC_signature_get_ctx_params_fn,
        signature_functions::get_ctx_params
    ),
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        OSSL_FUNC_signature_settable_ctx_params_fn,
        signature_functions::settable_ctx_params
    ),
    #[cfg(any())]
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        OSSL_FUNC_signature_set_ctx_params_fn,
        signature_functions::set_ctx_params
    ),
    OSSL_DISPATCH::END,
];

// TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
// https://docs.openssl.org/3.2/man7/provider-keymgmt/
pub(super) const KMGMT_FUNCTIONS: &[OSSL_DISPATCH] = &[
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
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_LOAD,
        OSSL_FUNC_keymgmt_load_fn,
        keymgmt_functions::load
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_MATCH,
        OSSL_FUNC_keymgmt_match_fn,
        keymgmt_functions::match_
    ),
    OSSL_DISPATCH::END,
];

pub(super) use decoder_functions::DER2PrivateKeyInfo as DECODER_DER2PrivateKeyInfo;
pub(super) use decoder_functions::DER2SubjectPublicKeyInfo as DECODER_DER2SubjectPublicKeyInfo;
pub(super) use encoder_functions::PrivateKeyInfo2DER as ENCODER_PrivateKeyInfo2DER;
pub(super) use encoder_functions::PrivateKeyInfo2PEM as ENCODER_PrivateKeyInfo2PEM;
pub(super) use encoder_functions::PrivateKeyInfo2Text as ENCODER_PrivateKeyInfo2Text;
pub(super) use encoder_functions::PubKeyStructureless2Text as ENCODER_PubKeyStructureless2Text;
pub(super) use encoder_functions::SubjectPublicKeyInfo2DER as ENCODER_SubjectPublicKeyInfo2DER;
pub(super) use encoder_functions::SubjectPublicKeyInfo2PEM as ENCODER_SubjectPublicKeyInfo2PEM;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::common::wycheproof::*;
    use signature::Verifier;
    use wycheproof::mldsa_verify;

    struct Mldsa44;

    impl SigAlgVerifyVariant for Mldsa44 {
        type PublicKey = keymgmt_functions::PublicKey;

        type Signature = signature::Signature;

        fn decode_pubkey(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
            Self::PublicKey::decode(bytes)
        }

        fn decode_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
            Self::Signature::try_from(bytes)
        }

        fn verify(
            pubkey: &Self::PublicKey,
            msg: &[u8],
            sig: &Self::Signature,
        ) -> Result<(), signature::Error> {
            pubkey.verify(msg, sig)
        }

        // This adapter does not support signatures with a non-empty ctx.
        fn verify_with_ctx(
            _pubkey: &Self::PublicKey,
            _msg: &[u8],
            _sig: &Self::Signature,
            _ctx: &[u8],
        ) -> Result<(), signature::Error> {
            Err(signature::Error::new())
        }
    }

    #[test]
    fn test_mldsa_44_verify_from_wycheproof() {
        run_mldsa_wycheproof_verify_tests::<Mldsa44>(mldsa_verify::TestName::MlDsa44Verify);
    }

    use signature::{SignatureBytes, SignatureEncoding, Signer};
    use wycheproof::mldsa_sign;

    impl SigAlgSignVariant for Mldsa44 {
        type PrivateKey = keymgmt_functions::PrivateKey;

        type Signature = signature::Signature;

        fn decode_privkey(bytes: &[u8]) -> anyhow::Result<Self::PrivateKey> {
            Self::PrivateKey::decode(bytes)
        }

        fn try_sign(
            privkey: &Self::PrivateKey,
            msg: &[u8],
            //deterministic: bool,
        ) -> Result<Self::Signature, signature::Error> {
            Self::PrivateKey::try_sign(privkey, msg)
        }

        fn try_sign_with_ctx(
            _privkey: &Self::PrivateKey,
            _msg: &[u8],
            _ctx: &[u8],
            //deterministic: bool,
        ) -> Result<Self::Signature, signature::Error> {
            // this adapter doesn't implement signing with ctx yet
            Err(signature::Error::new())
        }

        fn encode_signature(sig: &Self::Signature) -> Vec<u8> {
            Vec::from(sig.to_bytes().as_ref())
        }
    }

    #[test]
    fn test_mldsa_44_sign_seed_from_wycheproof() {
        run_mldsa_wycheproof_sign_tests::<Mldsa44>(
            mldsa_sign::TestName::MlDsa44SignSeed,
            // pqclean doesn't support deterministic ML-DSA
            false,
        );
    }

    #[test]
    fn test_mldsa_44_sign_noseed_from_wycheproof() {
        run_mldsa_wycheproof_sign_tests::<Mldsa44>(
            mldsa_sign::TestName::MlDsa44SignNoSeed,
            // pqclean doesn't support deterministic ML-DSA
            false,
        );
    }
}

use crate as aurora;
use crate::adapters::ObjSigId;

use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::forge;
use aurora::traits::*;
use aurora::OpenSSLProvider;
use aurora::{handleResult, named};
use bindings::{
    CONST_OSSL_PARAM, OSSL_ALGORITHM, OSSL_OP_DECODER, OSSL_OP_ENCODER, OSSL_OP_KEYMGMT,
};
use openssl_provider_forge::bindings::OSSL_OP_SIGNATURE;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='pqclean'";

#[allow(non_snake_case)]
pub(crate) mod MLDSA44;
#[allow(non_snake_case)]
pub(crate) mod MLDSA65;
#[allow(non_snake_case)]
pub(crate) mod MLDSA65_Ed25519;
#[allow(non_snake_case)]
pub(crate) mod MLDSA87;

#[derive(Debug)]
struct PQCleanAdapter;

impl AdapterContextTrait for PQCleanAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let signature_algorithms = Box::new([
            {
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::SIG_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::SIG_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::SIG_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::SIG_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_SIGNATURE, signature_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([
            {
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        // FIXME: probably this should be a const/static
        let decoder_algorithms = Box::new([
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2SubjectPublicKeyInfo as AlgDecoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2PrivateKeyInfo as AlgDecoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2SubjectPublicKeyInfo as AlgDecoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2PrivateKeyInfo as AlgDecoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2SubjectPublicKeyInfo as AlgDecoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2PrivateKeyInfo as AlgDecoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2SubjectPublicKeyInfo as AlgDecoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Decoder;
                use Alg::DECODER_DER2PrivateKeyInfo as AlgDecoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgDecoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);

        handle.register_algorithms(OSSL_OP_DECODER, decoder_algorithms.into_iter())?;

        let encoder_algorithms = Box::new([
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2DER as AlgEncoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2PEM as AlgEncoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2DER as AlgEncoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2PEM as AlgEncoder;
                use MLDSA44 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2DER as AlgEncoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2PEM as AlgEncoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2DER as AlgEncoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2PEM as AlgEncoder;
                use MLDSA65 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2DER as AlgEncoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2PEM as AlgEncoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2DER as AlgEncoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2PEM as AlgEncoder;
                use MLDSA87 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2DER as AlgEncoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_PrivateKeyInfo2PEM as AlgEncoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2DER as AlgEncoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use forge::operations::transcoders::Encoder;
                use Alg::ENCODER_SubjectPublicKeyInfo2PEM as AlgEncoder;
                use MLDSA65_Ed25519 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
                    implementation: AlgEncoder::DISPATCH_TABLE.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);

        handle.register_algorithms(OSSL_OP_ENCODER, encoder_algorithms.into_iter())?;

        Ok(())
    }

    #[named]
    fn register_capabilities(
        &self,
        handle: &mut super::AdaptersHandle,
    ) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let tls_sigalgs = [
            MLDSA44::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA44::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            MLDSA87::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA87::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            MLDSA65_Ed25519::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
        ];
        for a in tls_sigalgs {
            let first: &bindings::OSSL_PARAM = a.first().unwrap_or(&CONST_OSSL_PARAM::END);
            let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);
            handle.register_capability(c"TLS-SIGALG", ptr)?;
        }
        Ok(())
    }

    #[named]
    fn register_obj_sigids(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        // XXX the .unwrap()s here aren't very nice, we may want to do something about that
        let obj_sigids = vec![
            (
                MLDSA44::SIGALG_OID.unwrap(),
                MLDSA44::NAME,
                MLDSA44::LONG_NAME,
                None,
            ),
            (
                MLDSA65::SIGALG_OID.unwrap(),
                MLDSA65::NAME,
                MLDSA65::LONG_NAME,
                None,
            ),
            (
                MLDSA87::SIGALG_OID.unwrap(),
                MLDSA87::NAME,
                MLDSA87::LONG_NAME,
                None,
            ),
            (
                MLDSA65_Ed25519::SIGALG_OID.unwrap(),
                MLDSA65_Ed25519::NAME,
                MLDSA65_Ed25519::LONG_NAME,
                None,
            ),
        ];
        // XXX FIXME: quick hack
        let obj_sigids: Vec<_> = obj_sigids
            .iter()
            .map(|(oid, sn, ln, digest_name)| ObjSigId {
                oid,
                short_name: sn,
                long_name: ln,
                digest_name: *digest_name,
            })
            .collect();

        for obj_sigid in obj_sigids {
            handle.register_obj_sigid(obj_sigid)?;
        }

        Ok(())
    }
}

#[named]
pub fn init(handle: &mut super::AdaptersHandle) -> Result<(), OurError> {
    trace!(target: log_target!(), "{}", "Called!");
    let ourctx = PQCleanAdapter {};
    handle.register_adapter(ourctx);
    Ok(())
}

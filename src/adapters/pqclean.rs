use crate as aurora;
use crate::adapters::ObjSigId;

use super::common::macros;
use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::forge;
use aurora::traits::*;
use aurora::ProviderInstance;
use aurora::{handleResult, named};
use bindings::{CONST_OSSL_PARAM, OSSL_OP_DECODER, OSSL_OP_ENCODER, OSSL_OP_KEYMGMT};
use macros::{algorithm_to_register, decoder_to_register, encoder_to_register};
use openssl_provider_forge::bindings::OSSL_OP_SIGNATURE;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='pqclean'";

#[allow(non_snake_case)]
pub(crate) mod MLDSA44;
#[allow(non_snake_case)]
pub(crate) mod MLDSA44_Ed25519;
#[allow(non_snake_case)]
pub(crate) mod MLDSA65;
#[allow(non_snake_case)]
pub(crate) mod MLDSA65_Ed25519;
#[allow(non_snake_case)]
pub(crate) mod MLDSA87;

pub(super) mod helpers;

#[derive(Debug)]
struct PQCleanAdapter;

impl AdapterContextTrait for PQCleanAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let signature_algorithms = Box::new([
            algorithm_to_register!(MLDSA44, SIG_FUNCTIONS),
            algorithm_to_register!(MLDSA65, SIG_FUNCTIONS),
            algorithm_to_register!(MLDSA87, SIG_FUNCTIONS),
            algorithm_to_register!(MLDSA65_Ed25519, SIG_FUNCTIONS),
            algorithm_to_register!(MLDSA44_Ed25519, SIG_FUNCTIONS),
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_SIGNATURE, signature_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([
            algorithm_to_register!(MLDSA44, KMGMT_FUNCTIONS),
            algorithm_to_register!(MLDSA65, KMGMT_FUNCTIONS),
            algorithm_to_register!(MLDSA87, KMGMT_FUNCTIONS),
            algorithm_to_register!(MLDSA65_Ed25519, KMGMT_FUNCTIONS),
            algorithm_to_register!(MLDSA44_Ed25519, KMGMT_FUNCTIONS),
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        // FIXME: probably this should be a const/static
        let decoder_algorithms = Box::new([
            // MLDSA44
            decoder_to_register!(MLDSA44, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(MLDSA44, DECODER_DER2PrivateKeyInfo),
            // MLDSA65
            decoder_to_register!(MLDSA65, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(MLDSA65, DECODER_DER2PrivateKeyInfo),
            // MLDSA87
            decoder_to_register!(MLDSA87, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(MLDSA87, DECODER_DER2PrivateKeyInfo),
            // MLDSA65_Ed25519
            decoder_to_register!(MLDSA65_Ed25519, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(MLDSA65_Ed25519, DECODER_DER2PrivateKeyInfo),
            // MLDSA44_Ed25519
            decoder_to_register!(MLDSA44_Ed25519, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(MLDSA44_Ed25519, DECODER_DER2PrivateKeyInfo),
        ]);

        handle.register_algorithms(OSSL_OP_DECODER, decoder_algorithms.into_iter())?;

        let encoder_algorithms = Box::new([
            // MLDSA44
            encoder_to_register!(MLDSA44, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(MLDSA44, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(MLDSA44, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(MLDSA44, ENCODER_SubjectPublicKeyInfo2PEM),
            encoder_to_register!(MLDSA44, ENCODER_PubKeyStructureless2Text),
            // MLDSA65
            encoder_to_register!(MLDSA65, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(MLDSA65, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(MLDSA65, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(MLDSA65, ENCODER_SubjectPublicKeyInfo2PEM),
            encoder_to_register!(MLDSA65, ENCODER_PubKeyStructureless2Text),
            // MLDSA87
            encoder_to_register!(MLDSA87, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(MLDSA87, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(MLDSA87, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(MLDSA87, ENCODER_SubjectPublicKeyInfo2PEM),
            encoder_to_register!(MLDSA87, ENCODER_PubKeyStructureless2Text),
            // MLDSA65_Ed25519
            encoder_to_register!(MLDSA65_Ed25519, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(MLDSA65_Ed25519, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(MLDSA65_Ed25519, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(MLDSA65_Ed25519, ENCODER_SubjectPublicKeyInfo2PEM),
            encoder_to_register!(MLDSA65_Ed25519, ENCODER_PubKeyStructureless2Text),
            // MLDSA44_Ed25519
            encoder_to_register!(MLDSA44_Ed25519, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(MLDSA44_Ed25519, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(MLDSA44_Ed25519, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(MLDSA44_Ed25519, ENCODER_SubjectPublicKeyInfo2PEM),
            encoder_to_register!(MLDSA44_Ed25519, ENCODER_PubKeyStructureless2Text),
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
            // ------ MLDSA44
            MLDSA44::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA44::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            // ------ MLDSA65
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            // ------ MLDSA87
            MLDSA87::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for better compatibility with OQS-provider
            MLDSA87::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
            // ------ MLDSA65_Ed25519
            MLDSA65_Ed25519::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // ------ MLDSA44_Ed25519
            MLDSA44_Ed25519::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
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

        let obj_sigids = vec![
            MLDSA44::OBJ_SIGID,
            MLDSA65::OBJ_SIGID,
            MLDSA87::OBJ_SIGID,
            MLDSA65_Ed25519::OBJ_SIGID,
            MLDSA44_Ed25519::OBJ_SIGID,
        ];

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

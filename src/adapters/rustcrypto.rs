use crate as aurora;
use crate::adapters::ObjSigId;

use super::common::macros;
use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::forge;
use aurora::traits::*;
use aurora::OpenSSLProvider;
use aurora::{handleResult, named};
use bindings::{CONST_OSSL_PARAM, OSSL_OP_DECODER, OSSL_OP_ENCODER, OSSL_OP_KEYMGMT};
use macros::{algorithm_to_register, decoder_to_register, encoder_to_register};
use openssl_provider_forge::bindings::OSSL_OP_SIGNATURE;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='rustcrypto'";

#[allow(non_snake_case)]
pub(crate) mod SLHDSASHAKE192f;
#[allow(non_snake_case)]
pub(crate) mod SLHDSASHAKE256s;

#[derive(Debug)]
struct RustCryptoAdapter;

impl AdapterContextTrait for RustCryptoAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let signature_algorithms = Box::new([
            algorithm_to_register!(SLHDSASHAKE192f, SIG_FUNCTIONS),
            algorithm_to_register!(SLHDSASHAKE256s, SIG_FUNCTIONS),
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_SIGNATURE, signature_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([
            algorithm_to_register!(SLHDSASHAKE192f, KMGMT_FUNCTIONS),
            algorithm_to_register!(SLHDSASHAKE256s, KMGMT_FUNCTIONS),
        ]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        // FIXME: probably this should be a const/static
        let decoder_algorithms = Box::new([
            // SLHDSASHAKE192f
            decoder_to_register!(SLHDSASHAKE192f, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(SLHDSASHAKE192f, DECODER_DER2PrivateKeyInfo),
            // SLHDSASHAKE256s
            decoder_to_register!(SLHDSASHAKE256s, DECODER_DER2SubjectPublicKeyInfo),
            decoder_to_register!(SLHDSASHAKE256s, DECODER_DER2PrivateKeyInfo),
        ]);

        handle.register_algorithms(OSSL_OP_DECODER, decoder_algorithms.into_iter())?;

        let encoder_algorithms = Box::new([
            // SLHDSASHAKE192f
            encoder_to_register!(SLHDSASHAKE192f, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(SLHDSASHAKE192f, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(SLHDSASHAKE192f, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(SLHDSASHAKE192f, ENCODER_SubjectPublicKeyInfo2PEM),
            // SLHDSASHAKE256s
            encoder_to_register!(SLHDSASHAKE256s, ENCODER_PrivateKeyInfo2DER),
            encoder_to_register!(SLHDSASHAKE256s, ENCODER_PrivateKeyInfo2PEM),
            encoder_to_register!(SLHDSASHAKE256s, ENCODER_SubjectPublicKeyInfo2DER),
            encoder_to_register!(SLHDSASHAKE256s, ENCODER_SubjectPublicKeyInfo2PEM),
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
            SLHDSASHAKE192f::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            SLHDSASHAKE256s::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
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

        let obj_sigids = vec![SLHDSASHAKE192f::OBJ_SIGID, SLHDSASHAKE256s::OBJ_SIGID];

        for obj_sigid in obj_sigids {
            handle.register_obj_sigid(obj_sigid)?;
        }

        Ok(())
    }
}

#[named]
pub fn init(handle: &mut super::AdaptersHandle) -> Result<(), OurError> {
    trace!(target: log_target!(), "{}", "Called!");
    let ourctx = RustCryptoAdapter {};
    handle.register_adapter(ourctx);
    Ok(())
}

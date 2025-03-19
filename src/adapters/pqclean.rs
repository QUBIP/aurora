use crate as aurora;

use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::forge;
use aurora::OpenSSLProvider;
use aurora::{handleResult, named};
use bindings::{CONST_OSSL_PARAM, OSSL_ALGORITHM, OSSL_OP_DECODER, OSSL_OP_KEYMGMT};
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='pqclean'";
const DECODER_PROPERTY_DEFINITION: &CStr =
    c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der'";

#[allow(non_snake_case)]
pub(crate) mod MLDSA65;

#[derive(Debug)]
struct PQCleanAdapter;

impl AdapterContextTrait for PQCleanAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        #[cfg(any())]
        let kem_algorithms = Box::new([
            {
                use X25519MLKEM768 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KEM_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use SecP256r1MLKEM768 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KEM_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);
        #[cfg(any())]
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_KEM, kem_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([{
            use MLDSA65 as Alg;
            OSSL_ALGORITHM {
                algorithm_names: Alg::NAMES.as_ptr(),
                property_definition: PROPERTY_DEFINITION.as_ptr(),
                implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                algorithm_description: Alg::DESCRIPTION.as_ptr(),
            }
        }]);
        // ownership transfers to the iterator which is transferred to the handle
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        Ok(())
    }

    #[named]
    fn register_capabilities(
        &self,
        handle: &mut super::AdaptersHandle,
    ) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let tls_sigalgs = [
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY,
            // Add second sigalg capability for MLDSA65, for better compatibility with OQS-provider
            MLDSA65::capabilities::tls_sigalg::OSSL_PARAM_ARRAY_OQSCOMP,
        ];
        for a in tls_sigalgs {
            let first: &bindings::OSSL_PARAM = a.first().unwrap_or(&CONST_OSSL_PARAM::END);
            let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);
            handle.register_capability(c"TLS-SIGALG", ptr)?;
        }
        Ok(())
    }

    #[named]
    fn register_decoders(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let decoder_algorithms = Box::new([{
            use MLDSA65 as Alg;
            OSSL_ALGORITHM {
                algorithm_names: Alg::NAMES.as_ptr(),
                property_definition: DECODER_PROPERTY_DEFINITION.as_ptr(),
                implementation: Alg::DECODER_FUNCTIONS.as_ptr(),
                algorithm_description: Alg::DESCRIPTION.as_ptr(),
            }
        }]);

        handle.register_algorithms(OSSL_OP_DECODER, decoder_algorithms.into_iter())?;

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

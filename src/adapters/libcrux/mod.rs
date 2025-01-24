use crate as aurora;

use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::OpenSSLProvider;
use bindings::{OSSL_ALGORITHM, OSSL_OP_KEM, OSSL_OP_KEYMGMT};
use function_name::named;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='libcrux'";

#[allow(non_snake_case)]
pub(crate) mod SecP256r1MLKEM768;
#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768;

#[derive(Debug)]
struct LibcruxAdapter;

impl AdapterContextTrait for LibcruxAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

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
        handle.register_algorithms(OSSL_OP_KEM, kem_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([
            {
                use X25519MLKEM768 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
            {
                use SecP256r1MLKEM768 as Alg;
                OSSL_ALGORITHM {
                    algorithm_names: Alg::NAMES.as_ptr(),
                    property_definition: PROPERTY_DEFINITION.as_ptr(),
                    implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                    algorithm_description: Alg::DESCRIPTION.as_ptr(),
                }
            },
        ]);
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        Ok(())
    }
}

#[named]
pub fn init(handle: &mut super::AdaptersHandle) -> Result<(), OurError> {
    trace!(target: log_target!(), "{}", "Called!");
    let ourctx = LibcruxAdapter {};
    handle.register_adapter(ourctx);
    Ok(())
}

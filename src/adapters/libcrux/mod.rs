use crate as aurora;

use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::OpenSSLProvider;
use bindings::{OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_OP_KEM, OSSL_OP_KEYMGMT};
use function_name::named;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;
pub(crate) use anyhow::anyhow;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='libcrux'";

#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768;
#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768Draft00;

#[derive(Debug)]
struct LibcruxAdapter;

impl AdapterContextTrait for LibcruxAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let kem_algorithms = Box::new([OSSL_ALGORITHM {
            algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
            property_definition: PROPERTY_DEFINITION.as_ptr(),
            implementation: X25519MLKEM768::KEM_FUNCTIONS.as_ptr(),
            algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
        }]);
        handle.register_algorithms(OSSL_OP_KEM, kem_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([OSSL_ALGORITHM {
            algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
            property_definition: PROPERTY_DEFINITION.as_ptr(),
            implementation: X25519MLKEM768::KMGMT_FUNCTIONS.as_ptr(),
            algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
        }]);
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        Ok(())
    }
}

impl LibcruxAdapter {
    #[cfg(any())]
    #[named]
    fn get_algorithms(&self) -> HashMap<u32, Vec<OSSL_ALGORITHM>> {
        trace!(target: log_target!(), "{}", "Called!");
        let mut algorithms = HashMap::new();
        let kem_algorithms = vec![OSSL_ALGORITHM {
            algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
            property_definition: PROPERTY_DEFINITION.as_ptr(),
            implementation: X25519MLKEM768::KEM_FUNCTIONS.as_ptr(),
            algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
        }];
        algorithms.insert(OSSL_OP_KEM, kem_algorithms);
        let keymgmt_algorithms = vec![OSSL_ALGORITHM {
            algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
            property_definition: PROPERTY_DEFINITION.as_ptr(),
            implementation: X25519MLKEM768::KMGMT_FUNCTIONS.as_ptr(),
            algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
        }];
        algorithms.insert(OSSL_OP_KEYMGMT, keymgmt_algorithms);
        algorithms
    }
}

#[named]
pub fn init(handle: &mut super::AdaptersHandle) -> Result<(), OurError> {
    trace!(target: log_target!(), "{}", "Called!");
    let ourctx = LibcruxAdapter {};
    handle.register_adapter(ourctx);
    Ok(())
}

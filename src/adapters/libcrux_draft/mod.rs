use crate as aurora;

use aurora::adapters::AdapterContextTrait;
use aurora::bindings;
use aurora::OpenSSLProvider;
use bindings::{OSSL_ALGORITHM, OSSL_OP_KEM, OSSL_OP_KEYMGMT};
use function_name::named;
use std::ffi::CStr;

pub(crate) type OurError = aurora::Error;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='libcruxdraft'";

#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768Draft00;

#[derive(Debug)]
pub(crate) struct LibcruxDraftAdapter;

impl AdapterContextTrait for LibcruxDraftAdapter {
    #[named]
    fn register_algorithms(&self, handle: &mut super::AdaptersHandle) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let kem_algorithms = Box::new([{
            use X25519MLKEM768Draft00 as Alg;
            OSSL_ALGORITHM {
                algorithm_names: Alg::NAMES.as_ptr(),
                property_definition: PROPERTY_DEFINITION.as_ptr(),
                implementation: Alg::KEM_FUNCTIONS.as_ptr(),
                algorithm_description: Alg::DESCRIPTION.as_ptr(),
            }
        }]);
        handle.register_algorithms(OSSL_OP_KEM, kem_algorithms.into_iter())?;

        let keymgmt_algorithms = Box::new([{
            use X25519MLKEM768Draft00 as Alg;
            OSSL_ALGORITHM {
                algorithm_names: Alg::NAMES.as_ptr(),
                property_definition: PROPERTY_DEFINITION.as_ptr(),
                implementation: Alg::KMGMT_FUNCTIONS.as_ptr(),
                algorithm_description: Alg::DESCRIPTION.as_ptr(),
            }
        }]);
        handle.register_algorithms(OSSL_OP_KEYMGMT, keymgmt_algorithms.into_iter())?;

        Ok(())
    }

    #[named]
    fn register_capabilities(
        &self,
        handle: &mut super::AdaptersHandle,
    ) -> Result<(), aurora::Error> {
        trace!(target: log_target!(), "{}", "Called!");

        let tlsgroups = [X25519MLKEM768Draft00::capabilities::tls_group::OSSL_PARAM_ARRAY];
        for a in tlsgroups {
            use crate::osslparams::CONST_OSSL_PARAM;
            let first: &bindings::OSSL_PARAM = a.first().unwrap_or(&CONST_OSSL_PARAM::END);
            let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);
            handle.register_capability(c"TLS-GROUP", ptr)?;
        }
        Ok(())
    }
}

#[named]
pub fn init(handle: &mut super::AdaptersHandle) -> Result<(), OurError> {
    trace!(target: log_target!(), "{}", "Called!");
    let ourctx = LibcruxDraftAdapter {};
    handle.register_adapter(ourctx);
    Ok(())
}

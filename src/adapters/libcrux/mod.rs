use crate::OpenSSLProvider;
use bindings::{OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_OP_KEM, OSSL_OP_KEYMGMT};
use function_name::named;
use rust_openssl_core_provider::bindings;
use std::{collections::HashMap, ffi::CStr};

use super::AdapterContextTrait;

pub(crate) type OurError = anyhow::Error;
pub(crate) use anyhow::anyhow;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='libcrux'";

#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768;
#[allow(non_snake_case)]
pub(crate) mod X25519MLKEM768Draft00;

#[derive(Debug)]
pub(crate) struct LibcruxAdapter;

impl AdapterContextTrait for LibcruxAdapter {
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

pub fn init(super_ctx: &mut super::Contexts) -> Result<(), OurError> {
    let ourctx = LibcruxAdapter {};
    super_ctx.register(ourctx);
    Ok(())
}

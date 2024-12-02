use function_name::named;
use rust_openssl_core_provider::bindings::{OSSL_ALGORITHM, OSSL_DISPATCH};
use std::ffi::CStr;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP':x.qubip.adapter='libcrux'";

#[allow(non_snake_case)]
mod X25519MLKEM768 {
    use super::*;

    // Ensure proper null-terminated C string
    // https://docs.openssl.org/master/man7/provider/#algorithm-naming
    pub const NAMES: &CStr = c"X25519MLKEM768";

    pub const DESCRIPTION: &CStr = c"This is a description";

    // https://docs.openssl.org/master/man7/provider-kem/
    pub const KEM_FUNCTIONS: [OSSL_DISPATCH; 1] = [
        OSSL_DISPATCH::END,
    ];

    // https://docs.openssl.org/master/man7/provider-keymgmt/
    pub const KMGMT_FUNCTIONS: [OSSL_DISPATCH; 1] = [
        OSSL_DISPATCH::END,
    ];
}

#[derive(Debug)]
pub struct AdapterContext {
    op_kem_ptr: Option<*const OSSL_ALGORITHM>,
    op_keymgmt_ptr: Option<*const OSSL_ALGORITHM>,
}

impl Default for AdapterContext {
    fn default() -> Self {
        Self {
            op_kem_ptr: Default::default(),
            op_keymgmt_ptr: Default::default(),
        }
    }
}

impl AdapterContext {
    #[named]
    pub fn get_op_kem(&mut self) -> *const OSSL_ALGORITHM {
        debug!(target: log_target!(), "{}", "Called!");
        match self.op_kem_ptr {
            Some(ptr) => ptr,
            None => {
                // Dynamically create the OP_KEM array
                let array = vec![
                    OSSL_ALGORITHM {
                        algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
                        property_definition: PROPERTY_DEFINITION.as_ptr(), // Ensure proper null-terminated C string
                        implementation: X25519MLKEM768::KEM_FUNCTIONS.as_ptr(),
                        algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
                    },
                    OSSL_ALGORITHM::END,
                ]
                .into_boxed_slice();

                let raw_ptr = Box::into_raw(array) as *const OSSL_ALGORITHM;
                self.op_kem_ptr = Some(raw_ptr);
                raw_ptr
            }
        }
    }

    #[named]
    pub fn get_op_keymgmt(&mut self) -> *const OSSL_ALGORITHM {
        debug!(target: log_target!(), "{}", "Called!");
        match self.op_keymgmt_ptr {
            Some(ptr) => ptr,
            None => {
                // Dynamically create the OP_KEYMGMT array
                let array = vec![
                    OSSL_ALGORITHM {
                        algorithm_names: X25519MLKEM768::NAMES.as_ptr(),
                        property_definition: PROPERTY_DEFINITION.as_ptr(),
                        implementation: X25519MLKEM768::KMGMT_FUNCTIONS.as_ptr(),
                        algorithm_description: X25519MLKEM768::DESCRIPTION.as_ptr(),
                    },
                    OSSL_ALGORITHM::END,
                ]
                .into_boxed_slice();

                let raw_ptr = Box::into_raw(array) as *const OSSL_ALGORITHM;
                self.op_keymgmt_ptr = Some(raw_ptr);
                raw_ptr
            }
        }
    }
}

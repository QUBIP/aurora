use crate::OpenSSLProvider;
use bindings::{OSSL_ALGORITHM, OSSL_DISPATCH};
use function_name::named;
use rust_openssl_core_provider::bindings;
use std::ffi::CStr;

const PROPERTY_DEFINITION: &CStr = c"x.author='QUBIP',x.qubip.adapter='libcrux'";

#[allow(non_snake_case)]
mod X25519MLKEM768 {
    use super::*;
    use bindings::dispatch_table_entry;
    use bindings::{OSSL_FUNC_kem_decapsulate_fn, OSSL_FUNC_KEM_DECAPSULATE};
    use bindings::{OSSL_FUNC_kem_decapsulate_init_fn, OSSL_FUNC_KEM_DECAPSULATE_INIT};
    use bindings::{OSSL_FUNC_kem_encapsulate_fn, OSSL_FUNC_KEM_ENCAPSULATE};
    use bindings::{OSSL_FUNC_kem_encapsulate_init_fn, OSSL_FUNC_KEM_ENCAPSULATE_INIT};
    use bindings::{OSSL_FUNC_kem_freectx_fn, OSSL_FUNC_KEM_FREECTX};
    use bindings::{OSSL_FUNC_kem_newctx_fn, OSSL_FUNC_KEM_NEWCTX};

    // Ensure proper null-terminated C string
    // https://docs.openssl.org/master/man7/provider/#algorithm-naming
    pub(super) const NAMES: &CStr = c"X25519MLKEM768";

    // Ensure proper null-terminated C string
    pub(super) const DESCRIPTION: &CStr = c"This is a description";

    // https://docs.openssl.org/master/man7/provider-kem/
    pub(super) const KEM_FUNCTIONS: [OSSL_DISPATCH; 7] = [
        dispatch_table_entry!(
            OSSL_FUNC_KEM_NEWCTX,
            OSSL_FUNC_kem_newctx_fn,
            kem_functions::newctx
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEM_FREECTX,
            OSSL_FUNC_kem_freectx_fn,
            kem_functions::freectx
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEM_ENCAPSULATE_INIT,
            OSSL_FUNC_kem_encapsulate_init_fn,
            kem_functions::encapsulate_init
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEM_ENCAPSULATE,
            OSSL_FUNC_kem_encapsulate_fn,
            kem_functions::encapsulate
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEM_DECAPSULATE_INIT,
            OSSL_FUNC_kem_decapsulate_init_fn,
            kem_functions::decapsulate_init
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEM_DECAPSULATE,
            OSSL_FUNC_kem_decapsulate_fn,
            kem_functions::decapsulate
        ),
        OSSL_DISPATCH::END,
    ];

    // https://docs.openssl.org/master/man7/provider-keymgmt/
    pub(super) const KMGMT_FUNCTIONS: [OSSL_DISPATCH; 1] = [OSSL_DISPATCH::END];

    pub(super) mod kem_functions {
        use super::*;
        use bindings::ossl_param_st;
        use libc::{c_int, c_void};

        #[named]
        pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &mut OpenSSLProvider<'_> = vprovctx.try_into().unwrap();

            todo!("Create a new KEM ctx")
        }

        #[named]
        pub(super) extern "C" fn freectx(_vkemctx: *mut c_void) -> c_void {
            trace!(target: log_target!(), "{}", "Called!");

            todo!("Reclaim and drop vkemctx")
        }

        #[named]
        pub(super) extern "C" fn encapsulate_init(
            _vkemctx: *mut c_void,
            _provkey: *mut c_void,
            _params: *mut ossl_param_st,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");

            todo!("Init encapsulate operation ctx")
        }

        pub(super) use self::encapsulate_init as decapsulate_init;
        pub(super) use self::encapsulate_init as encapsulate;
        pub(super) use self::encapsulate_init as decapsulate;
    }
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
        trace!(target: log_target!(), "{}", "Called!");
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
        trace!(target: log_target!(), "{}", "Called!");
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

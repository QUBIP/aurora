use function_name::named;
use rust_openssl_core_provider::bindings::{OSSL_ALGORITHM, OSSL_DISPATCH};

const MLKEM_FUNCTIONS: [OSSL_DISPATCH; 1] = [
    OSSL_DISPATCH::END,
];

#[derive(Debug)]
pub struct AdapterContext {
    op_kem_ptr: Option<*const OSSL_ALGORITHM>,
}

impl Default for AdapterContext {
    fn default() -> Self {
        Self { op_kem_ptr: Default::default() }
    }
}

impl AdapterContext {
    #[named]
    pub fn get_op_kem(&mut self) -> *const OSSL_ALGORITHM {
        debug!(target: log_target!(), "{}", "Called!");
        match self.op_kem_ptr {
            Some(ptr) => ptr,
            None => {
                // Dynamically create the MLKEMPROV array
                let array = vec![
                    OSSL_ALGORITHM {
                        algorithm_names: c"MLKEM".as_ptr(), // Ensure proper null-terminated C string
                        property_definition: c"x.author='author'".as_ptr(), // Ensure proper null-terminated C string
                        implementation: MLKEM_FUNCTIONS.as_ptr(),
                        algorithm_description: std::ptr::null(),
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
}




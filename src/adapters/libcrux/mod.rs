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
    use bindings::{OSSL_FUNC_keymgmt_export_fn, OSSL_FUNC_KEYMGMT_EXPORT};
    use bindings::{OSSL_FUNC_keymgmt_export_types_ex_fn, OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX};
    use bindings::{OSSL_FUNC_keymgmt_free_fn, OSSL_FUNC_KEYMGMT_FREE};
    use bindings::{OSSL_FUNC_keymgmt_has_fn, OSSL_FUNC_KEYMGMT_HAS};
    use bindings::{OSSL_FUNC_keymgmt_import_fn, OSSL_FUNC_KEYMGMT_IMPORT};
    use bindings::{OSSL_FUNC_keymgmt_import_types_ex_fn, OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX};
    use bindings::{OSSL_FUNC_keymgmt_new_fn, OSSL_FUNC_KEYMGMT_NEW};

    // Ensure proper null-terminated C string
    // https://docs.openssl.org/master/man7/provider/#algorithm-naming
    pub(super) const NAMES: &CStr = c"X25519MLKEM768";

    // Ensure proper null-terminated C string
    pub(super) const DESCRIPTION: &CStr = c"X25519MLKEM768 from libcrux";

    // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
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

    // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
    // https://docs.openssl.org/master/man7/provider-keymgmt/
    pub(super) const KMGMT_FUNCTIONS: [OSSL_DISPATCH; 8] = [
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_NEW,
            OSSL_FUNC_keymgmt_new_fn,
            keymgmt_functions::new
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_FREE,
            OSSL_FUNC_keymgmt_free_fn,
            keymgmt_functions::free
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_HAS,
            OSSL_FUNC_keymgmt_has_fn,
            keymgmt_functions::has
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_IMPORT,
            OSSL_FUNC_keymgmt_import_fn,
            keymgmt_functions::import
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_EXPORT,
            OSSL_FUNC_keymgmt_export_fn,
            keymgmt_functions::export
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX,
            OSSL_FUNC_keymgmt_import_types_ex_fn,
            keymgmt_functions::import_types_ex
        ),
        dispatch_table_entry!(
            OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX,
            OSSL_FUNC_keymgmt_export_types_ex_fn,
            keymgmt_functions::export_types_ex
        ),
        OSSL_DISPATCH::END,
    ];

    mod kem_functions {
        use super::*;
        use bindings::ossl_param_st;
        use libc::{c_int, c_uchar, c_void};

        #[named]
        pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();

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

        #[named]
        pub(super) extern "C" fn decapsulate_init(
            _vkemctx: *mut c_void,
            _provkey: *mut c_void,
            _params: *mut ossl_param_st,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");

            todo!("Init decapsulate operation ctx")
        }

        #[named]
        pub(super) extern "C" fn encapsulate(
            _ctx: *mut c_void,
            _out: *mut c_uchar,
            _outlen: *mut usize,
            _secret: *mut c_uchar,
            _secretlen: *mut usize,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");

            todo!("Perform encapsulate")
        }

        #[named]
        pub(super) extern "C" fn decapsulate(
            _ctx: *mut c_void,
            _out: *mut c_uchar,
            _outlen: *mut usize,
            _in_: *const c_uchar,
            _inlen: usize,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");

            todo!("Perform decapsulate")
        }
    }

    mod keymgmt_functions {
        use super::*;
        use bindings::{ossl_param_st, OSSL_CALLBACK};
        use std::ffi::{c_int, c_void};

        #[named]
        pub(super) unsafe extern "C" fn new(vprovctx: *mut c_void) -> *mut c_void {
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
            todo!("Create a new key management ctx")
        }

        #[named]
        pub(super) unsafe extern "C" fn free(_keydata: *mut c_void) {
            trace!(target: log_target!(), "{}", "Called!");
            todo!("Free the key data")
        }

        #[named]
        pub(super) unsafe extern "C" fn has(
            _keydata: *const c_void,
            _selection: c_int,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");
            todo!("Check whether the given keydata contains the subsets of data indicated by the selector")
        }

        #[named]
        pub(super) unsafe extern "C" fn import(
            _keydata: *mut c_void,
            _selection: c_int,
            _params: *const ossl_param_st
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");
            todo!("import data indicated by selection into keydata with values taken from the params array")
        }

        #[named]
        pub(super) unsafe extern "C" fn export(
            _keydata: *mut c_void,
            _selection: c_int,
            _param_cb: OSSL_CALLBACK,
            _cbarg: *mut c_void,
        ) -> c_int {
            trace!(target: log_target!(), "{}", "Called!");
            todo!("extract values indicated by selection from keydata, create an OSSL_PARAM array with them, and call param_cb with that array as well as the given cbarg")
        }

        // I think using {import,export}_types_ex instead of the non-_ex variant means we only
        // support OSSL 3.2 and up, but I also think that's fine...?
        #[named]
        pub(super) unsafe extern "C" fn import_types_ex(
            vprovctx: *mut c_void,
            _selection: c_int,
        ) -> *const ossl_param_st {
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
            todo!("return a constant array of descriptor OSSL_PARAM(3) for data indicated by selection, for parameters that OSSL_FUNC_keymgmt_import() can handle")
        }

        #[named]
        pub(super) unsafe extern "C" fn export_types_ex(
            vprovctx: *mut c_void,
            _selection: c_int,
        ) -> *const ossl_param_st {
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
            todo!("return a constant array of descriptor OSSL_PARAM(3) for data indicated by selection, that the OSSL_FUNC_keymgmt_export() callback can expect to receive")
        }
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

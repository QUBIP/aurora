
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
pub(super) unsafe extern "C" fn has(_keydata: *const c_void, _selection: c_int) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    todo!("Check whether the given keydata contains the subsets of data indicated by the selector")
}

#[named]
pub(super) unsafe extern "C" fn gen(
    _genctx: *mut c_void,
    _cb: OSSL_CALLBACK,
    _cbarg: *mut c_void,
) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    todo!("perform keygen and call cb at regular intervals with progress indications")
}

#[named]
pub(super) unsafe extern "C" fn gen_cleanup(_genctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    todo!("clean up and free the key object generation context genctx")
}

#[named]
pub(super) unsafe extern "C" fn gen_init(
    vprovctx: *mut c_void,
    _selection: c_int,
    _params: *const ossl_param_st,
) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
    todo!("create the keygen context genctx; initialize it with selections; set params on the context if params is not null")
}

#[named]
pub(super) unsafe extern "C" fn import(
    _keydata: *mut c_void,
    _selection: c_int,
    _params: *const ossl_param_st,
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

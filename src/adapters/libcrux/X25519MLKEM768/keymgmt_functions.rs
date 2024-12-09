use super::*;
use bindings::{ossl_param_st, OSSL_CALLBACK};
use std::ffi::{c_int, c_void};

#[allow(dead_code)]
struct KeyPair {
    private: Option<libcrux_kem::PrivateKey>,
    public: Option<libcrux_kem::PublicKey>,
}

impl From<*mut c_void> for &mut KeyPair {
    #[named]
    fn from(vptr: *mut c_void) -> Self {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut c_void> for &mut KeyPair"
        );
        let ptr = vptr as *mut KeyPair;
        if ptr.is_null() {
            panic!("vptr was null");
        }
        unsafe { &mut *ptr }
    }
}

#[named]
pub(super) unsafe extern "C" fn new(vprovctx: *mut c_void) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();

    //todo!("Create a provider side key object.")

    // FIXME: we should probably wrap around the randomness provided by OSSL in their dispatch table
    let mut rng = rand::rngs::OsRng;
    warn!(target: log_target!(), "{}", "Using OsRng!");

    let (s, p) =
        libcrux_kem::key_gen(libcrux_kem::Algorithm::X25519MlKem768Draft00, &mut rng).unwrap();
    let keypair = Box::new(KeyPair {
        private: Some(s),
        public: Some(p),
    });

    return Box::into_raw(keypair).cast();
}

#[named]
pub(super) unsafe extern "C" fn free(vkey: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    let /* mut  */kp: Box<KeyPair> = unsafe { Box::from_raw(vkey.cast()) };
    //todo!("Cleanse the private key data")
    //todo!("Free the key data")
    drop(kp);
}

#[named]
pub(super) unsafe extern "C" fn has(_keydata: *const c_void, _selection: c_int) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    todo!("Check whether the given keydata contains the subsets of data indicated by the selector")
}

#[named]
pub(super) unsafe extern "C" fn gen(
    vgenctx: *mut c_void,
    _cb: OSSL_CALLBACK,
    _cbarg: *mut c_void,
) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    let _genctx: &mut GenCTX<'_> = vgenctx.into();

    // FIXME: we should probably wrap around the randomness provided by OSSL in their dispatch table
    let mut rng = rand::rngs::OsRng;
    warn!(target: log_target!(), "{}", "Using OsRng!");

    let (s, p) =
        libcrux_kem::key_gen(libcrux_kem::Algorithm::X25519MlKem768Draft00, &mut rng).unwrap();
    let keypair = Box::new(KeyPair {
        private: Some(s),
        public: Some(p),
    });

    let keypair_ptr = Box::into_raw(keypair);

    return keypair_ptr.cast();
    //todo!("perform keygen and call cb at regular intervals with progress indications")
}

#[named]
pub(super) unsafe extern "C" fn gen_cleanup(vgenctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    let /* mut  */genctx: Box<GenCTX> = unsafe { Box::from_raw(vgenctx.cast()) };
    //todo!("clean up and free the key object generation context genctx");
    drop(genctx);
}

struct GenCTX<'a> {
    _provctx: &'a OpenSSLProvider<'a>,
    _selection: c_int,
}

impl<'a> GenCTX<'a> {
    fn new(provctx: &'a OpenSSLProvider, selection: c_int) -> Self {
        Self {
            _provctx: provctx,
            _selection: selection,
        }
    }
}

impl<'a> From<*mut c_void> for &mut GenCTX<'a> {
    #[named]
    fn from(vctx: *mut c_void) -> Self {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut c_void> for &mut OpenSSLProvider<'a>"
        );
        let ctxp = vctx as *mut GenCTX;
        if ctxp.is_null() {
            panic!("vctx was null");
        }
        unsafe { &mut *ctxp }
    }
}

#[named]
pub(super) unsafe extern "C" fn gen_init(
    vprovctx: *mut c_void,
    selection: c_int,
    _params: *const ossl_param_st,
) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    let provctx: &OpenSSLProvider<'_> = vprovctx.into();
    let newctx = Box::new(GenCTX::new(provctx, selection));
    warn!(target: log_target!(), "Ignoring params!");
    //todo!("set params on the context if params is not null")
    let newctx_raw_ptr = Box::into_raw(newctx);

    return newctx_raw_ptr.cast();
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

#[named]
pub(super) unsafe extern "C" fn gen_set_params(
    _vgenctx: *mut c_void,
    _params: *const ossl_param_st
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    warn!(target: log_target!(), "{}", "Ignoring params!");
    //todo!("set genctx params");
    1
}

use crate::osslparams::EMPTY_PARAMS;

#[named]
pub(super) unsafe extern "C" fn gen_settable_params(
    _vgenctx: *mut c_void,
    vprovctx: *mut c_void,
) -> *const ossl_param_st {
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();
    //todo!("return pointer to array of settable genctx params")
    warn!(target: log_target!(), "{}", "TODO: return pointer to (non-empty) array of settable genctx params");

    EMPTY_PARAMS.as_ptr()
}

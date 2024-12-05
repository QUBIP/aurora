use super::*;
use bindings::{ossl_param_st, OSSL_CALLBACK, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY};
use rust_openssl_core_provider::osslparams::ossl_param_locate_raw;
use std::ffi::{c_int, c_void};

pub type PrivateKey = libcrux_kem::PrivateKey;
pub type PublicKey = libcrux_kem::PublicKey;

pub struct KeyPair {
    pub private: Option<PrivateKey>,
    pub public: Option<PublicKey>,
}

impl TryFrom<*mut c_void> for &mut KeyPair {
    type Error = anyhow::Error;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut c_void> for &mut KeyPair"
        );
        let ptr = vptr as *mut KeyPair;
        if ptr.is_null() {
            return Err(anyhow::anyhow!("vptr was null"));
        }
        Ok(unsafe { &mut *ptr })
    }
}

impl TryFrom<*mut core::ffi::c_void> for &KeyPair {
    type Error = anyhow::Error;

    #[named]
    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}", "impl<'a> TryFrom<*mut core::ffi::c_void> for &OpenSSLProvider<'a>");
        let r: &mut KeyPair = vctx.try_into()?;
        Ok(r)
    }
}

#[named]
pub(super) unsafe extern "C" fn new(vprovctx: *mut c_void) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    const ERROR_RET: *mut c_void = std::ptr::null_mut();

    let _prov: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

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
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };
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
    const ERROR_RET: *const ossl_param_st = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };
    todo!("return a constant array of descriptor OSSL_PARAM(3) for data indicated by selection, for parameters that OSSL_FUNC_keymgmt_import() can handle")
}

#[named]
pub(super) unsafe extern "C" fn export_types_ex(
    vprovctx: *mut c_void,
    _selection: c_int,
) -> *const ossl_param_st {
    const ERROR_RET: *const ossl_param_st = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };
    todo!("return a constant array of descriptor OSSL_PARAM(3) for data indicated by selection, that the OSSL_FUNC_keymgmt_export() callback can expect to receive")
}

#[named]
pub(super) unsafe extern "C" fn gen_set_params(
    _vgenctx: *mut c_void,
    _params: *const ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("set genctx params");
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "Ignoring params!");
        return 1;
    }
}

#[named]
pub(super) unsafe extern "C" fn gen_settable_params(
    _vgenctx: *mut c_void,
    vprovctx: *mut c_void,
) -> *const ossl_param_st {
    const ERROR_RET: *const ossl_param_st = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("return pointer to array of settable genctx params")
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "TODO: return pointer to (non-empty) array of settable genctx params");

        crate::osslparams::EMPTY_PARAMS.as_ptr()
    }
}

#[named]
pub(super) unsafe extern "C" fn get_params(
    vkeydata: *mut c_void,
    params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    let keydata: &KeyPair = vkeydata.try_into().unwrap();

    // TODO: handle errors responsibly!!!
    match ossl_param_locate_raw(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY).as_mut() {
        Some(p) => {
            match &keydata.public {
                Some(pubkey) => {
                    let bytes = pubkey.encode();
                    // might be nice to impl OSSLParamSetter<&Vec<u8>> and avoid .as_slice()
                    let _ = p.set(bytes.as_slice()); // set(&bytes)
                }
                None => (),
            }
        }
        None => (),
    }

    // Based on stepping through the code with gdb, OSSL also asks for params with the keys "bits",
    // "security-bits", and "max-size", but I'm not sure if responding to those is necessary.

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("get remaining keymgmt params (if any)")
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "TODO: get remaining keymgmt params (if any)");

        1
    }
}

#[named]
pub(super) unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const ossl_param_st {
    trace!(target: log_target!(), "{}", "Called!");
    const ERROR_RET: *const ossl_param_st = std::ptr::null();
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("return pointer to array of gettable keymgmt params")
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "TODO: return pointer to (non-empty) array of gettable keymgmt params");

        crate::osslparams::EMPTY_PARAMS.as_ptr()
    }
}

#[named]
pub(super) unsafe extern "C" fn set_params(
    _vkeydata: *mut c_void,
    _params: *const ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("set keymgmt params")
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "TODO: set keymgmt params");

        1
    }
}

#[named]
pub(super) unsafe extern "C" fn settable_params(vprovctx: *mut c_void) -> *const ossl_param_st {
    const ERROR_RET: *const ossl_param_st = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    #[cfg(not(debug_assertions))] // code compiled only in release builds
    {
        todo!("return pointer to array of settable keymgmt params")
    }

    #[cfg(debug_assertions)] // code compiled only in development builds
    {
        warn!(target: log_target!(), "{}", "TODO: return pointer to (non-empty) array of settable keymgmt params");

        crate::osslparams::EMPTY_PARAMS.as_ptr()
    }
}

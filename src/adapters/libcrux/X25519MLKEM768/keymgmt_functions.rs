use super::*;
use crate::{handleResult, OpenSSLProvider};
use bindings::{ossl_param_st, OSSL_CALLBACK, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY};
use rust_openssl_core_provider::osslparams::ossl_param_locate_raw;
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use std::ffi::{c_int, c_void};
use super::OurError as KMGMTError;

pub type PrivateKey = libcrux_kem::PrivateKey;
pub type PublicKey = libcrux_kem::PublicKey;

#[expect(dead_code)]
pub struct KeyPair<'a> {
    pub private: Option<PrivateKey>,
    pub public: Option<PublicKey>,
    provctx: &'a OpenSSLProvider<'a>,
}

pub(crate) type EncapsulatedKey = Vec<u8>;
pub(crate) type SharedSecret = Vec<u8>;

impl Decapsulate<EncapsulatedKey, SharedSecret> for KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn decapsulate(&self, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret, Self::Error> {
        trace!(target: log_target!(), "Called ");
        let ek = libcrux_kem::Ct::decode(
            libcrux_kem::Algorithm::X25519MlKem768Draft00,
            encapsulated_key,
        )
        .map_err(|e| anyhow!("libcrux_kem::Ct::decode returned {:?}", e))?;

        match &self.private {
            Some(sk) => {
                let ss = ek
                    .decapsulate(sk)
                    .map_err(|e| anyhow!("libcrux_kem::EK::decapsulate() returned {:?}", e))?;
                let ss = ss.encode();
                Ok(ss)
            }
            None => {
                error!(target: log_target!(), "Keypair is missing a private key");
                Err(anyhow!("Missing private key"))
            }
        }
    }
}

impl Encapsulate<EncapsulatedKey, SharedSecret> for KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncapsulatedKey, SharedSecret), Self::Error> {
        trace!(target: log_target!(), "Called ");
        match &self.public {
            Some(pk) => match pk.encapsulate(rng) {
                Ok((ss, ct)) => Ok((ct.encode(), ss.encode())),
                Err(e) => Err(anyhow!("{:?}", e)),
            },
            None => {
                error!(target: log_target!(), "Keypair is missing a public key");
                Err(anyhow!("Missing public key"))
            }
        }
    }
}

impl KeyPair<'_> {
    /// A convenience method to encapsulate a shared secret and generate a
    /// ciphertext (encapsulated key).
    ///
    /// # Description
    ///
    /// This function performs key encapsulation by securely generating a
    /// shared secret and the corresponding encapsulated key.
    /// It uses the pseudorandom number generator (PRNG) associated with this
    /// `KeyPair` (from the associated Provider Context).
    ///
    /// # Returns
    ///
    /// On success, returns a tuple containing:
    /// - `EncapsulatedKey`: The ciphertext to be transmitted to the other peer.
    /// - `SharedSecret`: The shared secret derived during the encapsulation.
    ///
    /// On failure, returns an `Error`.
    ///
    /// # Example
    ///
    /// ```
    /// # use your_crate::{KeyPair, EncapsulatedKey, SharedSecret, Error};
    /// # fn main() -> Result<(), Error> {
    /// let keypair = KeyPair::new();
    /// let (encapsulated_key, shared_secret) = keypair.encapsulate_ex()?;
    /// // Use the `encapsulated_key` and `shared_secret` as needed.
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if key encapsulation fails.
    #[named]
    pub fn encapsulate_ex(&self) -> Result<(EncapsulatedKey, SharedSecret), KMGMTError> {
        trace!(target: log_target!(), "Called ");

        let mut rng = {
            #[cfg(not(debug_assertions))] // code compiled only in release builds
            {
                let _prng = self.provctx.get_rng();
                todo!("Retrieve rng from provctx");
            }
            #[cfg(debug_assertions)] // code compiled only in development builds
            {
                // FIXME: clean this up and to the right thing above!
                warn!(target: log_target!(), "{}", "Using OsRng!");
                rand::rngs::OsRng
            }
        };

        self.encapsulate(&mut rng)
    }

    // No `decapsulate_ex`: decapsulate does not require extra randomness, so
    // we don't need a convenience method
}

impl TryFrom<*mut c_void> for &mut KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl TryFrom<*mut c_void> for &mut KeyPair"
        );
        let ptr = vptr as *mut KeyPair;
        if ptr.is_null() {
            return Err(anyhow::anyhow!("vptr was null"));
        }
        Ok(unsafe { &mut *ptr })
    }
}

impl TryFrom<*mut core::ffi::c_void> for &KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn try_from(vptr: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}", "impl<'a> TryFrom<*mut core::ffi::c_void> for &KeyPair<'a>");
        let r: &mut KeyPair = vptr.try_into()?;
        Ok(r)
    }
}

#[named]
pub(super) unsafe extern "C" fn new(vprovctx: *mut c_void) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    let provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    let mut rng = {
        #[cfg(not(debug_assertions))] // code compiled only in release builds
        {
            let _prng = self.provctx.get_rng();
            todo!("Retrieve rng from provctx");
        }
        #[cfg(debug_assertions)] // code compiled only in development builds
        {
            // FIXME: clean this up and to the right thing above!
            warn!(target: log_target!(), "{}", "Using OsRng!");
            rand::rngs::OsRng
        }
    };

    let (s, p) =
        libcrux_kem::key_gen(libcrux_kem::Algorithm::X25519MlKem768Draft00, &mut rng).unwrap();
    let keypair = Box::new(KeyPair {
        private: Some(s),
        public: Some(p),
        provctx: provctx,
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
    let genctx: &mut GenCTX<'_> = vgenctx.try_into().unwrap();

    let mut rng = {
        #[cfg(not(debug_assertions))] // code compiled only in release builds
        {
            let _prng = self.provctx.get_rng();
            todo!("Retrieve rng from provctx");
        }
        #[cfg(debug_assertions)] // code compiled only in development builds
        {
            // FIXME: clean this up and to the right thing above!
            warn!(target: log_target!(), "{}", "Using OsRng!");
            rand::rngs::OsRng
        }
    };

    let (s, p) =
        libcrux_kem::key_gen(libcrux_kem::Algorithm::X25519MlKem768Draft00, &mut rng).unwrap();
    let keypair = Box::new(KeyPair {
        private: Some(s),
        public: Some(p),
        provctx: genctx.provctx,
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
    provctx: &'a OpenSSLProvider<'a>,
    _selection: c_int,
}

impl<'a> GenCTX<'a> {
    fn new(provctx: &'a OpenSSLProvider, selection: c_int) -> Self {
        Self {
            provctx: provctx,
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

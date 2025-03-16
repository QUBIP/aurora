use super::OurError as KMGMTError;
use super::*;
use bindings::{
    CONST_OSSL_PARAM, OSSL_CALLBACK, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use forge::{keymgmt::selection::Selection, osslparams};
use kem::{Decapsulate, Encapsulate};
use osslparams::OSSLParam;
use rand_core::CryptoRngCore;
use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
};

pub struct PublicKey {
    pub ec_share: libcrux_kem::PublicKey,
    pub mlkem_share: libcrux_kem::PublicKey,
}

pub struct PrivateKey {
    pub ec_share: libcrux_kem::PrivateKey,
    pub mlkem_share: libcrux_kem::PrivateKey,
}

impl PublicKey {
    const EC_LEN: usize = 65;
    const MLKEM_LEN: usize = 1184;

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        debug_assert_eq!(bytes.len(), Self::EC_LEN + Self::MLKEM_LEN);
        let bytes: [u8; Self::EC_LEN + Self::MLKEM_LEN] = bytes.try_into()?;
        let ec = &bytes[..Self::EC_LEN];
        let point_format = ec[0];
        if point_format != 0x04 {
            return Err(anyhow!(
                "Invalid point format for EC share: {point_format:0X?}"
            ));
        }
        let ec = &ec[1..];
        let mlkem = &bytes[Self::EC_LEN..];

        let mlkem = libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::MlKem768, mlkem)
            .map_err(|e| anyhow!("libcrux_kem::PublicKey::decode (MLKEM768) returned {:?}", e))?;
        let ec =
            libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::Secp256r1, ec).map_err(|e| {
                anyhow!(
                    "libcrux_kem::PublicKey::decode (secp256r1) returned {:?}",
                    e
                )
            })?;
        Ok(Self {
            mlkem_share: mlkem,
            ec_share: ec,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend(self.ec_share.encode());
        out.extend(self.mlkem_share.encode());
        out
    }
}

impl Encapsulate<EncapsulatedKey, SharedSecret> for PublicKey {
    type Error = KMGMTError;

    #[named]
    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncapsulatedKey, SharedSecret), Self::Error> {
        trace!(target: log_target!(), "Called ");

        let (mlkem_ss, mlkem_ct) = self.mlkem_share.encapsulate(rng).map_err(|e| {
            anyhow!(
                "libcrux_kem::PublicKey::encapsulate (MLKEM768) returned {:?}",
                e
            )
        })?;
        let (ec_ss, ec_ct) = self.ec_share.encapsulate(rng).map_err(|e| {
            anyhow!(
                "libcrux_kem::PublicKey::encapsulate (secp256r1) returned {:?}",
                e
            )
        })?;

        let ss = InnerSharedSecret {
            ec_share: ec_ss,
            mlkem_share: mlkem_ss,
        };
        let ss = ss.encode();

        let ct = InnerEncapsulatedKey {
            ec_share: ec_ct,
            mlkem_share: mlkem_ct,
        };
        let ct = ct.encode();

        Ok((ct, ss))
    }
}

impl PrivateKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ec_share.encode();
        out.extend(self.mlkem_share.encode());
        out
    }
}

#[expect(dead_code)]
pub struct KeyPair<'a> {
    pub private: Option<PrivateKey>,
    pub public: Option<PublicKey>,
    provctx: &'a OpenSSLProvider<'a>,
}

impl<'a> Debug for KeyPair<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let private = match &self.private {
            #[cfg(not(debug_assertions))] // code compiled only in release builds
            Some(_) => {
                todo!("remove private key printing also from development builds");
                format!("{}", "present")
            }
            #[cfg(debug_assertions)] // code compiled only in development builds
            Some(p) => {
                format!("{:?}", p.encode())
            }
            None => format!("{:?}", None::<()>),
        };
        let public = match &self.public {
            Some(p) => format!("{:?}", p.encode()),
            None => format!("{:?}", None::<()>),
        };
        f.debug_struct("KeyPair")
            .field("private", &private)
            .field("public", &public)
            .finish()
    }
}

pub(crate) type EncapsulatedKey = Vec<u8>;
pub(crate) type SharedSecret = Vec<u8>;

struct InnerEncapsulatedKey {
    ec_share: libcrux_kem::Ct,
    mlkem_share: libcrux_kem::Ct,
}
struct InnerSharedSecret {
    ec_share: libcrux_kem::Ss,
    mlkem_share: libcrux_kem::Ss,
}

impl InnerEncapsulatedKey {
    const MLKEM_LEN: usize = 1088;
    const EC_LEN: usize = 65;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend(self.ec_share.encode());
        out.extend(self.mlkem_share.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        debug_assert_eq!(bytes.len(), Self::MLKEM_LEN + Self::EC_LEN);
        let bytes: [u8; Self::MLKEM_LEN + Self::EC_LEN] = bytes.try_into()?;
        let ec = &bytes[..Self::EC_LEN];
        let point_format = ec[0];
        if point_format != 0x04 {
            return Err(anyhow!(
                "Invalid point format for EC share: {point_format:0X?}"
            ));
        }
        let ec = &ec[1..];
        let mlkem = &bytes[Self::EC_LEN..];

        let mlkem = libcrux_kem::Ct::decode(libcrux_kem::Algorithm::MlKem768, mlkem)
            .map_err(|e| anyhow!("libcrux_kem::Ct::decode (MLKEM768) returned {:?}", e))?;
        let ec = libcrux_kem::Ct::decode(libcrux_kem::Algorithm::Secp256r1, ec)
            .map_err(|e| anyhow!("libcrux_kem::Ct::decode (secp256r1) returned {:?}", e))?;
        Ok(Self {
            mlkem_share: mlkem,
            ec_share: ec,
        })
    }

    pub fn decapsulate(&self, sk: &PrivateKey) -> Result<InnerSharedSecret, KMGMTError> {
        let mlkem_share = self
            .mlkem_share
            .decapsulate(&sk.mlkem_share)
            .map_err(|e| anyhow!("libcrux_kem::Ct::decapsulate (MLKEM768) returned {:?}", e))?;
        let ec_share = self
            .ec_share
            .decapsulate(&sk.ec_share)
            .map_err(|e| anyhow!("libcrux_kem::Ct::decapsulate (secp256r1) returned {:?}", e))?;
        Ok(InnerSharedSecret {
            ec_share,
            mlkem_share,
        })
    }
}

impl InnerSharedSecret {
    const MLKEM_LEN: usize = 32;
    const EC_LEN: usize = 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ec_share.encode();
        out.truncate(Self::EC_LEN);
        out.extend(self.mlkem_share.encode());
        out
    }
}

impl Decapsulate<EncapsulatedKey, SharedSecret> for KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn decapsulate(&self, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret, Self::Error> {
        trace!(target: log_target!(), "Called ");
        let ek = InnerEncapsulatedKey::decode(encapsulated_key)?;

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
            Some(pk) => pk.encapsulate(rng),
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

    pub(crate) fn expected_ct_size(&self) -> Result<usize, KMGMTError> {
        return Ok(InnerEncapsulatedKey::EC_LEN + InnerEncapsulatedKey::MLKEM_LEN);
    }

    pub(crate) fn expected_ss_size(&self) -> Result<usize, KMGMTError> {
        // FIXME: should not be hardcoded
        return Ok(InnerSharedSecret::MLKEM_LEN + InnerSharedSecret::EC_LEN);
    }

    // No `decapsulate_ex`: decapsulate does not require extra randomness, so
    // we don't need a convenience method
}

impl<'a> KeyPair<'a> {
    #[named]
    fn new(provctx: &'a OpenSSLProvider) -> Self {
        trace!(target: log_target!(), "Called");
        KeyPair {
            private: None,
            public: None,
            provctx: provctx,
        }
    }

    #[named]
    fn generate(provctx: &'a OpenSSLProvider) -> Self {
        trace!(target: log_target!(), "Called");
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

        let (ec_priv, ec_pub) =
            libcrux_kem::key_gen(libcrux_kem::Algorithm::Secp256r1, &mut rng).unwrap();
        let (mlkem_priv, mlkem_pub) =
            libcrux_kem::key_gen(libcrux_kem::Algorithm::MlKem768, &mut rng).unwrap();
        #[cfg(not(debug_assertions))] // code compiled only in release builds
        {
            // FIXME: unwrap() should go away and errors properly handled
            todo!("Remove unwrap");
        }

        KeyPair {
            private: Some(PrivateKey {
                ec_share: ec_priv,
                mlkem_share: mlkem_priv,
            }),
            public: Some(PublicKey {
                ec_share: ec_pub,
                mlkem_share: mlkem_pub,
            }),
            provctx,
        }
    }

    #[cfg(test)]
    #[named]
    fn generate_new(provctx: &'a OpenSSLProvider) -> Self {
        trace!(target: log_target!(), "Called");
        let genctx = GenCTX::new(provctx, Selection::KEYPAIR);
        let r = genctx.generate();

        Self {
            private: r.private,
            public: r.public,
            provctx,
        }
    }
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

    let keypair: Box<KeyPair<'_>> = Box::new(KeyPair::new(provctx));
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
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let genctx: &mut GenCTX<'_> = handleResult!(vgenctx.try_into());

    let keypair: Box<KeyPair<'_>> = Box::new(genctx.generate());

    let keypair_ptr = Box::into_raw(keypair);

    return keypair_ptr.cast();
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
    selection: Selection,
}

impl<'a> GenCTX<'a> {
    fn new(provctx: &'a OpenSSLProvider, selection: Selection) -> Self {
        Self {
            provctx: provctx,
            selection: selection,
        }
    }

    #[named]
    fn generate(&self) -> KeyPair<'_> {
        trace!(target: log_target!(), "Called");
        if !self.selection.contains(Selection::KEYPAIR) {
            trace!(target: log_target!(), "Returning empty keypair due to selection bits {:?}", self.selection);
            return KeyPair::new(self.provctx);
        }
        debug!(target: log_target!(), "Generating a new KeyPair");

        KeyPair::generate(self.provctx)
    }
}

impl<'a> TryFrom<*mut c_void> for &mut GenCTX<'a> {
    type Error = KMGMTError;

    #[named]
    fn try_from(vctx: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut c_void> for &mut GenCTX<'a>"
        );
        let ctxp = vctx as *mut GenCTX;
        if ctxp.is_null() {
            panic!("vctx was null");
        }
        Ok(unsafe { &mut *ctxp })
    }
}

#[named]
pub(super) unsafe extern "C" fn gen_init(
    vprovctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());
    let selection: Selection = handleResult!((selection as u32).try_into());
    let newctx = Box::new(GenCTX::new(provctx, selection));

    if !params.is_null() {
        warn!(target: log_target!(), "Ignoring params!");
        //todo!("set params on the context if params is not null")
    }

    let newctx_raw_ptr = Box::into_raw(newctx);

    return newctx_raw_ptr.cast();
}

#[named]
pub(super) unsafe extern "C" fn import(
    _keydata: *mut c_void,
    _selection: c_int,
    _params: *const OSSL_PARAM,
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

const HANDLED_KEY_TYPES: [OSSL_PARAM; 3] = [
    OSSL_PARAM {
        key: OSSL_PKEY_PARAM_PUB_KEY.as_ptr(),
        data_type: OSSL_PARAM_OCTET_STRING,
        data: std::ptr::null::<std::ffi::c_void>() as *mut std::ffi::c_void,
        data_size: 0,
        return_size: 0,
    },
    OSSL_PARAM {
        key: OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(),
        data_type: OSSL_PARAM_OCTET_STRING,
        data: std::ptr::null::<std::ffi::c_void>() as *mut std::ffi::c_void,
        data_size: 0,
        return_size: 0,
    },
    osslparams::OSSL_PARAM_END,
];

// I think using {import,export}_types_ex instead of the non-_ex variant means we only
// support OSSL 3.2 and up, but I also think that's fine...?
#[named]
pub(super) unsafe extern "C" fn import_types_ex(
    vprovctx: *mut c_void,
    selection: c_int,
) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());
    let selection: Selection = handleResult!((selection as u32).try_into());

    if selection.intersects(Selection::KEYPAIR) {
        return HANDLED_KEY_TYPES.as_ptr();
    }
    ERROR_RET
}

#[named]
pub(super) unsafe extern "C" fn export_types_ex(
    vprovctx: *mut c_void,
    _selection: c_int,
) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
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
    _params: *const OSSL_PARAM,
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
) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
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
    params: *mut OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");
    let keydata: &KeyPair = handleResult!(vkeydata.try_into());

    let params = match OSSLParam::try_from(params) {
        Ok(params) => params,
        Err(e) => {
            error!(target: log_target!(), "Failed decoding params: {:?}", e);
            return ERROR_RET;
        }
    };

    for mut p in params {
        let key = match p.get_key() {
            Some(key) => key,
            None => {
                error!(target: log_target!(), "Param without valid key {:?}", p);
                return ERROR_RET;
            }
        };

        if key == OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY {
            match &keydata.public {
                Some(pubkey) => {
                    let bytes = pubkey.encode();
                    // might be nice to impl OSSLParamSetter<&Vec<u8>> and avoid .as_slice()
                    let _ = p.set(bytes.as_slice()); // set(&bytes)
                }
                #[expect(unreachable_code)]
                None => {
                    unreachable!("Unexpectedly the public key was empty?");
                    return ERROR_RET;
                }
            }
        } else {
            debug!(target: log_target!(), "Ignoring param {:?}", key);
        }
    }
    return SUCCESS;
}

#[named]
pub(super) unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    trace!(target: log_target!(), "{}", "Called!");
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    static LIST: &[CONST_OSSL_PARAM] = &[
        OSSLParam::new_const_octetstring(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, None),
        CONST_OSSL_PARAM::END,
    ];

    let first: &bindings::OSSL_PARAM = &LIST[0];
    let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);

    return ptr;
}

#[named]
pub(super) unsafe extern "C" fn set_params(
    vkeydata: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");
    let keydata: &mut KeyPair = handleResult!(vkeydata.try_into());

    let params = match OSSLParam::try_from(params) {
        Ok(params) => params,
        Err(e) => {
            error!(target: log_target!(), "Failed decoding params: {:?}", e);
            return ERROR_RET;
        }
    };

    for p in params {
        let key = match p.get_key() {
            Some(key) => key,
            None => {
                error!(target: log_target!(), "Param without valid key {:?}", p);
                return ERROR_RET;
            }
        };

        if key == OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY {
            let bytes: &[u8] = match p.get() {
                Some(bytes) => bytes,
                None => handleResult!(Err(anyhow!("Invalid ENCODED_PUBLIC_KEY"))),
            };
            debug!(target: log_target!(), "The received encoded public key is (len: {}): {:X?}", bytes.len(), bytes);

            keydata.public = Some(handleResult!(PublicKey::decode(bytes)));
        } else {
            debug!(target: log_target!(), "Ignoring param {:?}", key);
        }
    }
    return SUCCESS;
}

#[named]
pub(super) unsafe extern "C" fn settable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    static LIST: &[CONST_OSSL_PARAM] = &[
        OSSLParam::new_const_octetstring(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, None),
        CONST_OSSL_PARAM::END,
    ];

    let first: &bindings::OSSL_PARAM = &LIST[0];
    let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);

    return ptr;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::new_provctx_for_testing;

    #[test]
    fn test_loopback_kex() {
        let provctx = new_provctx_for_testing();

        let client_kp = KeyPair::generate_new(&provctx);

        let (ct, ss) = client_kp.encapsulate_ex().unwrap();

        let decapsulated_ss = client_kp.decapsulate(&ct).unwrap();

        assert_eq!(ss, decapsulated_ss);
    }

    #[test]
    fn test_full_kex() {
        let provctx = new_provctx_for_testing();

        let client_kp = KeyPair::generate_new(&provctx);

        let client_keyshare = client_kp.public.as_ref().unwrap().encode();
        // client sends its keyshare

        // server decodes the received keyshare
        let server_recv_keyshare = client_keyshare;
        let server_decoded_keyshare = PublicKey::decode(&server_recv_keyshare).unwrap();
        let serverside_kp = KeyPair {
            private: None,
            public: Some(server_decoded_keyshare),
            provctx: &provctx,
        };

        let (ct, ss) = serverside_kp.encapsulate_ex().unwrap();
        // server sends back CT as its keyshare
        let server_keyshare = ct;

        let decapsulated_ss = client_kp.decapsulate(&server_keyshare).unwrap();

        assert_eq!(ss, decapsulated_ss);
    }
}

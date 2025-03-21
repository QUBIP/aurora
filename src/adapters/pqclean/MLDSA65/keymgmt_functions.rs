use super::OurError as KMGMTError;
use super::*;
use bindings::{
    OSSL_CALLBACK, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
};
use forge::{bindings, keymgmt::selection::Selection, osslparams::*};
use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
};

pub(crate) const PUBKEY_LEN: usize = PublicKey::byte_len();
pub(crate) const SECRETKEY_LEN: usize = PrivateKey::byte_len();
pub(crate) const SIGNATURE_LEN: usize = PrivateKey::signature_bytes();

// The wrapped key from the pqcrypto crate has to be public, or else we can't access it to use it
// with the pqcrypto sign and verify functions.
#[derive(PartialEq)]
pub struct PublicKey(pub pqcrypto_mldsa::mldsa65::PublicKey);

#[derive(PartialEq)]
pub struct PrivateKey(pub pqcrypto_mldsa::mldsa65::SecretKey);

impl PublicKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        let k =
            <pqcrypto_mldsa::mldsa65::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::PublicKey::from_bytes (MLDSA65) returned {:?}",
                    e
                )
            })?;
        Ok(Self(k))
    }

    pub fn encode(&self) -> Vec<u8> {
        let Self(ref k) = self;
        <pqcrypto_mldsa::mldsa65::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(k)
            .to_vec()
    }

    pub const fn byte_len() -> usize {
        pqcrypto_mldsa::mldsa65::public_key_bytes()
    }

    pub const fn signature_bytes() -> usize {
        PrivateKey::signature_bytes()
    }
}

impl PrivateKey {
    pub fn encode(&self) -> Vec<u8> {
        let Self(ref k) = self;
        <pqcrypto_mldsa::mldsa65::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(k)
            .to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        let k =
            <pqcrypto_mldsa::mldsa65::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(
                bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::SecretKey::from_bytes (MLDSA65) returned {:?}",
                    e
                )
            })?;
        Ok(Self(k))
    }

    pub const fn byte_len() -> usize {
        pqcrypto_mldsa::mldsa65::secret_key_bytes()
    }

    pub const fn signature_bytes() -> usize {
        pqcrypto_mldsa::mldsa65::signature_bytes()
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
                format!("{:02x?}", p.encode())
            }
            None => format!("{:?}", None::<()>),
        };
        let public = match &self.public {
            Some(p) => format!("{:02x?}", p.encode()),
            None => format!("{:?}", None::<()>),
        };
        f.debug_struct("KeyPair")
            .field("private", &private)
            .field("public", &public)
            .finish()
    }
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
    pub(super) fn from_parts(
        provctx: &'a OpenSSLProvider,
        private: Option<PrivateKey>,
        public: Option<PublicKey>,
    ) -> Self {
        trace!(target: log_target!(), "Called");
        KeyPair {
            private,
            public,
            provctx,
        }
    }

    #[named]
    fn generate(provctx: &'a OpenSSLProvider) -> Self {
        trace!(target: log_target!(), "Called");

        // Isn't it weird that this operation can't fail? What does the pqclean implementation do if
        // it can't find a randomness source or it can't allocate memory or something?
        let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();

        KeyPair {
            private: Some(PrivateKey(sk)),
            public: Some(PublicKey(pk)),
            provctx,
        }
    }

    #[cfg(test)]
    #[named]
    pub(crate) fn generate_new(provctx: &'a OpenSSLProvider) -> Self {
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

impl TryFrom<*mut c_void> for &KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn try_from(vptr: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}", "impl<'a> TryFrom<*mut core::ffi::c_void> for &KeyPair<'a>");
        let r: &mut KeyPair = vptr.try_into()?;
        Ok(r)
    }
}

impl TryFrom<*const c_void> for &KeyPair<'_> {
    type Error = KMGMTError;

    #[named]
    fn try_from(vptr: *const c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}", "impl<'a> TryFrom<*const c_void> for &KeyPair<'a>");
        let mut_vptr = vptr as *mut c_void;
        let r: &mut KeyPair = mut_vptr.try_into()?;
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
pub(super) unsafe extern "C" fn has(vkeydata: *const c_void, selection: c_int) -> c_int {
    const ERROR_RET: c_int = 0;

    trace!(target: log_target!(), "{}", "Called!");

    let selection: u32 = selection.try_into().unwrap();

    // From https://github.com/openssl/openssl/blob/fb55383c65bb47eef3bf5f73be5a0ad41d81bb3f/providers/implementations/keymgmt/ml_dsa_kmgmt.c#L145-L155
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 {
        return 1; // the selection is not missing
    }

    let keydata: &KeyPair = handleResult!(vkeydata.try_into());

    // from https://github.com/openssl/openssl/blob/fb55383c65bb47eef3bf5f73be5a0ad41d81bb3f/crypto/ml_dsa/ml_dsa_key.c#L285-L297
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        // Note that the public key always exists if there is a private key
        if keydata.public.is_none() {
            return 0; // No public key
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && keydata.private.is_none() {
            return 0; // No private key
        }
        return 1;
    }

    return 0;
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
        trace!(target: log_target!(), "Generating a new KeyPair");

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
    OSSL_PARAM::END,
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
    let _keydata: &KeyPair = handleResult!(vkeydata.try_into());

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

        if key == OSSL_PKEY_PARAM_BITS {
            const BITS: c_int = 8 * (PUBKEY_LEN as c_int);
            let _ = handleResult!(p.set(BITS));
        } else if key == OSSL_PKEY_PARAM_MAX_SIZE {
            let _ = handleResult!(p.set(SIGNATURE_LEN as c_int));
        } else if key == OSSL_PKEY_PARAM_SECURITY_BITS {
            let _ = handleResult!(p.set(super::SECURITY_BITS as c_int));
        } else if key == OSSL_PKEY_PARAM_MANDATORY_DIGEST {
            let _ = handleResult!(p.set(c""));
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
        OSSLParam::new_const_int::<c_int>(OSSL_PKEY_PARAM_BITS, None),
        OSSLParam::new_const_int::<c_int>(OSSL_PKEY_PARAM_MAX_SIZE, None),
        OSSLParam::new_const_int::<c_int>(OSSL_PKEY_PARAM_SECURITY_BITS, None),
        OSSLParam::new_const_utf8string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, None),
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

        if false && key == OSSL_PKEY_PARAM_SECURITY_BITS {
            unreachable!();
            //let bytes: &[u8] = match p.get() {
            //    Some(bytes) => bytes,
            //    None => handleResult!(Err(anyhow!("Invalid ENCODED_PUBLIC_KEY"))),
            //};
            //debug!(target: log_target!(), "The received encoded public key is (len: {}): {:X?}", bytes.len(), bytes);

            //keydata.public = Some(handleResult!(PublicKey::decode(bytes)));
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

    static LIST: &[CONST_OSSL_PARAM] = &[CONST_OSSL_PARAM::END];

    let first: &bindings::OSSL_PARAM = &LIST[0];
    let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);

    return ptr;
}

#[named]
/// Implements key loading by object reference, also a constructor for a new Key object
///
/// Refer to [provider-keymgmt(7ossl)] and [provider-object(7ossl)].
///
/// # Notes
///
/// This function is tightly integrated with the
/// [`OSSL_FUNC_decoder_decode_fn`][provider-decoder(7ossl)]
/// exposed by [decoders registered][`super::decoder_functions`]
/// for [this algorithm][`super`]
/// by [this adapter][`super::super`].
///
/// Eventually this function is called by the callback passed to OSSL_FUNC_decoder_decode_fn
/// hence they must agree on how the reference is being passed around.
///
/// [provider-keymgmt(7ossl)]: https://docs.openssl.org/master/man7/provider-keymgmt/
/// [provider-object(7ossl)]: https://docs.openssl.org/master/man7/provider-object/
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
pub(super) unsafe extern "C" fn load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");

    assert_eq!(reference_sz, std::mem::size_of::<KeyPair>());
    if reference.is_null() {
        error!(target: log_target!(), "reference should not be NULL");
        unreachable!()
    }

    let keypair = handleResult!(<&KeyPair>::try_from(reference as *mut c_void));
    debug!(target: log_target!(), "keypair: {keypair:#?}");

    return std::ptr::from_ref(keypair).cast_mut() as *mut c_void;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCTX<'a> {
        provctx: OpenSSLProvider<'a>,
    }

    fn setup<'a>() -> Result<TestCTX<'a>, OurError> {
        use crate::tests::new_provctx_for_testing;

        crate::tests::common::setup()?;

        let provctx = new_provctx_for_testing();

        let testctx = TestCTX { provctx };

        Ok(testctx)
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let testctx = setup().expect("Failed to initialize test setup");

        let provctx = testctx.provctx;

        let keypair = KeyPair::generate_new(&provctx);

        match (keypair.public, keypair.private) {
            (None, None) => panic!("No public or private key generated"),
            (None, Some(_)) => panic!("No public key generated"),
            (Some(_), None) => panic!("No private key generated"),
            (Some(pk), Some(sk)) => {
                let encoded_pk = pk.encode();
                let roundtripped_pk = PublicKey::decode(&encoded_pk).unwrap();
                // we can't use assert_eq! without having a Debug impl for both arguments
                assert!(pk == roundtripped_pk);

                let encoded_sk = sk.encode();
                let roundtripped_sk = PrivateKey::decode(&encoded_sk).unwrap();
                assert!(sk == roundtripped_sk);
            }
        }
    }
}

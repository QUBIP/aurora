use super::*;
use bindings::{
    OSSL_CALLBACK, OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_MANDATORY_DIGEST,
    OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
    OSSL_PKEY_PARAM_SECURITY_BITS,
};
use forge::{
    bindings,
    operations::keymgmt::selection::Selection,
    operations::signature::{Signer, VerificationError, Verifier},
    ossl_callback::OSSLCallback,
    osslparams::*,
};
use pqcrypto_traits::sign::DetachedSignature;
use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
};

use pqcrypto_mldsa::mldsa87 as backend_module;

use super::OurError as KMGMTError;
type OurResult<T> = anyhow::Result<T, KMGMTError>;

use super::signature::{Signature, SignatureBytes, SignatureEncoding};

pub(crate) const PUBKEY_LEN: usize = PublicKey::byte_len();
pub(crate) const SECRETKEY_LEN: usize = PrivateKey::byte_len();
pub(crate) const SIGNATURE_LEN: usize = PrivateKey::signature_bytes();

// The wrapped key from the pqcrypto crate has to be public, or else we can't access it to use it
// with the pqcrypto sign and verify functions.
#[derive(PartialEq)]
pub struct PublicKey(backend_module::PublicKey);

#[derive(PartialEq)]
pub struct PrivateKey(backend_module::SecretKey);

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey").field(&"<opaque field>").finish()
    }
}

impl PublicKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        let k = <backend_module::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(bytes)
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::PublicKey::from_bytes (MLDSA87) returned {:?}",
                    e
                )
            })?;
        Ok(Self(k))
    }

    pub fn encode(&self) -> Vec<u8> {
        let Self(ref k) = self;
        <backend_module::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(k).to_vec()
    }

    pub const fn byte_len() -> usize {
        backend_module::public_key_bytes()
    }

    pub const fn signature_bytes() -> usize {
        PrivateKey::signature_bytes()
    }

    #[named]
    pub fn from_DER(pk_der_bytes: &[u8]) -> OurResult<Self> {
        use asn_definitions::PublicKey as ASNPublicKey;

        trace!(target: log_target!(), "{}", "Called!");

        let decodedpubkey: ASNPublicKey;
        let slice = match pk_der_bytes.len() {
            PUBKEY_LEN => pk_der_bytes,

            #[cfg(any())]
            _ => {
                decodedpubkey = match rasn::der::decode(pk_der_bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(target: log_target!(), "Failed to decode the inner public key: {e:?}");
                        return Err(OurError::from(e));
                    }
                };

                debug!(target: log_target!(), "Parsed public key material out of ASN.1 for decoding!");

                let slice: &[u8] = decodedpubkey.0.as_slice();
                slice
            }

            #[cfg(not(any()))]
            _ => {
                let _ = decodedpubkey;
                unreachable!();
            }
        };

        debug_assert_eq!(slice.len(), PUBKEY_LEN);
        let pubkey = Self::decode(slice)?;

        Ok(pubkey)
    }

    #[named]
    pub fn to_DER(&self) -> OurResult<Vec<u8>> {
        trace!(target: log_target!(), "{}", "Called!");

        Ok(self.encode())
    }
}

impl Verifier<Signature> for PublicKey {
    #[named]
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), forge::crypto::signature::Error> {
        let sig = sig.to_bytes();
        let sig = sig.as_ref();
        use pqcrypto_traits::sign::DetachedSignature;
        let sig = backend_module::DetachedSignature::from_bytes(sig).map_err(|e| {
            error!(target: log_target!(), "{e:?}");
            forge::crypto::signature::Error::from_source(
                VerificationError::GenericVerificationError,
            )
        })?;
        backend_module::verify_detached_signature(&sig, msg, &self.0)
            .map_err(map_into_VerificationError)
            .map_err(forge::crypto::signature::Error::from_source)
    }
}

#[named]
fn map_into_VerificationError(
    value: pqcrypto_traits::sign::VerificationError,
) -> VerificationError {
    match value {
        pqcrypto_traits::sign::VerificationError::InvalidSignature => {
            VerificationError::InvalidSignature
        }
        pqcrypto_traits::sign::VerificationError::UnknownVerificationError => {
            VerificationError::GenericVerificationError
        }
        e => {
            warn!(target: log_target!(), "Unknown error {e:#?}");
            VerificationError::GenericVerificationError
        }
    }
}

impl PrivateKey {
    pub fn encode(&self) -> Vec<u8> {
        let Self(ref k) = self;
        <backend_module::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(k).to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        let k = <backend_module::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(bytes)
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::SecretKey::from_bytes (MLDSA87) returned {:?}",
                    e
                )
            })?;
        Ok(Self(k))
    }

    pub const fn byte_len() -> usize {
        backend_module::secret_key_bytes()
    }

    pub const fn signature_bytes() -> usize {
        backend_module::signature_bytes()
    }

    /// Derive a matching public key from this private key
    pub fn derive_public_key(&self) -> Option<PublicKey> {
        let pk = super::helpers::derive_public_key(&self.0);
        pk.map(|inner| PublicKey(inner))
    }

    #[named]
    pub fn from_DER(sk_der_bytes: &[u8]) -> OurResult<(Self, Option<PublicKey>)> {
        use asn_definitions::PrivateKey as ASNPrivateKey;

        let decodedprivkey = match rasn::der::decode::<ASNPrivateKey>(sk_der_bytes) {
            Ok(p) => p,
            Err(e) => {
                error!(target: log_target!(), "Failed to decode the inner private key: {e:?}");
                return Err(OurError::from(e));
            }
        };

        debug!(target: log_target!(), "Parsed private key material out of ASN.1 for decoding!");

        let (privkey, opt_pubkey) = match decodedprivkey {
            ASNPrivateKey::seed(_seed) => unimplemented!(),
            ASNPrivateKey::expandedKey(expandedKey) => {
                let slice: &[u8] = &expandedKey;
                let privkey = keymgmt_functions::PrivateKey::decode(slice)?;

                // We need to derive a public key from the private key, without a seed
                let pubkey = match privkey.derive_public_key() {
                    Some(k) => k,
                    None => {
                        error!(target: log_target!(), "Could not derive the public key from the inner private key");
                        return Err(anyhow!(
                            "Could not derive the public key from the inner private key"
                        ));
                    }
                };
                (privkey, Some(pubkey))
            }
            ASNPrivateKey::both(_private_key_both) => unimplemented!(),
        };
        Ok((privkey, opt_pubkey))
    }

    #[named]
    pub fn to_DER(&self) -> OurResult<Vec<u8>> {
        use asn_definitions::PrivateKey as ASNPrivateKey;

        let raw_sk_bytes = self.encode();
        let asn_sk = ASNPrivateKey::expandedKey(raw_sk_bytes.into());
        let asn_sk_bytes = match rasn::der::encode(&asn_sk) {
            Ok(v) => v,
            Err(e) => {
                error!(target: log_target!(), "Failed to encode private key: {e:?}");
                return Err(OurError::from(e));
            }
        };
        Ok(asn_sk_bytes)
    }
}

impl Signer<Signature> for PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, forge::crypto::signature::Error> {
        let Self(ref sk) = self;
        let signature = backend_module::detached_sign(msg, sk);
        Signature::try_from(signature.as_bytes())
            .map_err(|e| forge::crypto::signature::Error::from_source(e))
    }
}

#[expect(dead_code)]
pub struct KeyPair<'a> {
    pub private: Option<PrivateKey>,
    pub public: Option<PublicKey>,
    provctx: &'a ProviderInstance<'a>,
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
    fn new(provctx: &'a ProviderInstance) -> Self {
        trace!(target: log_target!(), "Called");
        KeyPair {
            private: None,
            public: None,
            provctx: provctx,
        }
    }

    #[named]
    pub(super) fn from_parts(
        provctx: &'a ProviderInstance,
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
    fn generate(provctx: &'a ProviderInstance) -> Result<Self, KMGMTError> {
        trace!(target: log_target!(), "Called");

        // Isn't it weird that this operation can't fail? What does the pqclean implementation do if
        // it can't find a randomness source or it can't allocate memory or something?
        let (pk, sk) = backend_module::keypair();

        Ok(KeyPair {
            private: Some(PrivateKey(sk)),
            public: Some(PublicKey(pk)),
            provctx,
        })
    }

    #[cfg(test)]
    #[named]
    pub(crate) fn generate_new(provctx: &'a ProviderInstance) -> Result<Self, KMGMTError> {
        trace!(target: log_target!(), "Called");
        let genctx = GenCTX::new(provctx, Selection::KEYPAIR);
        let r = genctx.generate()?;

        Ok(Self {
            private: r.private,
            public: r.public,
            provctx,
        })
    }
}

impl<'a> Signer<Signature> for KeyPair<'a> {
    #[named]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, forge::crypto::signature::Error> {
        trace!(target: log_target!(), "Called");

        let sk = self
            .private
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "This keypair does not have a private key, so it cannot generate signatures"
                )
            })
            .map_err(forge::crypto::signature::Error::from_source)?;
        Ok(sk.try_sign(msg)?)
    }
}

impl<'a> Verifier<Signature> for KeyPair<'a> {
    #[named]
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), forge::crypto::signature::Error> {
        trace!(target: log_target!(), "Called");

        let pk = self
            .public
            .as_ref()
            .ok_or_else(|| {
                anyhow!("This keypair does not have a public key, so it cannot verify signatures")
            })
            .map_err(|e| {
                error!("{e:#}");
                forge::crypto::signature::Error::from_source(
                    VerificationError::GenericVerificationError,
                )
            })?;
        pk.verify(msg, sig)
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
    let provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());

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

    let keypair = handleResult!(genctx.generate());
    let keypair: Box<KeyPair<'_>> = Box::new(keypair);

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
    provctx: &'a ProviderInstance<'a>,
    selection: Selection,
}

impl<'a> GenCTX<'a> {
    fn new(provctx: &'a ProviderInstance, selection: Selection) -> Self {
        Self {
            provctx: provctx,
            selection: selection,
        }
    }

    #[named]
    fn generate(&self) -> Result<KeyPair<'_>, KMGMTError> {
        trace!(target: log_target!(), "Called");
        if !self.selection.contains(Selection::KEYPAIR) {
            trace!(target: log_target!(), "Returning empty keypair due to selection bits {:?}", self.selection);
            return Ok(KeyPair::new(self.provctx));
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
    let provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());
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

#[cfg(feature = "export")]
#[named]
pub(super) unsafe extern "C" fn export(
    vkeydata: *mut c_void,
    selection: c_int,
    param_cb: OSSL_CALLBACK,
    cbarg: *mut c_void,
) -> c_int {
    // based on OpenSSL's providers/implementations/keymgmt/ml_dsa_keymgmt.c:ml_dsa_export()
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let selection = selection as u32;
    let keydata: &KeyPair = handleResult!(vkeydata.try_into());

    if vkeydata.is_null() || ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        return ERROR_RET;
    }

    let include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    debug!(target: log_target!(), "include_private is: {}", include_private);

    // In OpenSSL, they either 1) give the private key and/or the seed (if the private key was
    // requested, or 2) give only the public key (if the private key wasn't requested). Since the
    // former could require storing 1 or 2 elements in a params array, they allocate an array of 3
    // elements (for it and the END marker). We don't have a way to get the seed out of the pqcrypto
    // crate, unless I'm missing something, but for now I've kept the "put these in a list" design
    // anyway (instead of putting it in an Option), in case we find a way to get the seed out later.
    // (They need to be transformed into an END-terminated slice eventually anyway.)
    let mut params: Vec<CONST_OSSL_PARAM> = Vec::new();
    // I want to do something concise like this, but I haven't figured out the right incantations to
    // get around the "cannot move out of shared reference" stuff.
    /*
    let (key_part, param_name) = if include_private {
        (keydata.private.map(|k| k.encode()), OSSL_PKEY_PARAM_PRIV_KEY)
    } else {
        (keydata.public.map(|k| k.encode()), OSSL_PKEY_PARAM_PUB_KEY)
    };
    // (transform key_part from Option<Vec<u8>> to Option<&[i8]> before the next line)
    params.push(OSSLParam::new_const_octetstring(param_name, key_part));
    */
    if include_private {
        if let Some(private_key) = &keydata.private {
            debug!(target: log_target!(), "exporting private key");
            let bytes = private_key.encode();
            params.push(OSSLParam::new_const_octetstring(
                OSSL_PKEY_PARAM_PRIV_KEY,
                Some(
                    bytes
                        .iter()
                        .map(|&b| b as i8)
                        .collect::<Vec<i8>>()
                        .as_slice(),
                ),
            ));
        }
    } else {
        if let Some(public_key) = &keydata.public {
            debug!(target: log_target!(), "exporting public key");
            let bytes = public_key.encode();
            params.push(OSSLParam::new_const_octetstring(
                OSSL_PKEY_PARAM_PUB_KEY,
                Some(
                    bytes
                        .iter()
                        .map(|&b| b as i8)
                        .collect::<Vec<i8>>()
                        .as_slice(),
                ),
            ));
        }
    }

    // if we couldn't find the key part they wanted, there's nothing more to do
    if params.is_empty() {
        return ERROR_RET;
    }

    // but if we did find it, then we construct the params slice for the callback and call it!
    params.push(CONST_OSSL_PARAM::END);
    let params = params.into_boxed_slice();
    let cb = handleResult!(OSSLCallback::try_new(param_cb, cbarg));
    cb.call(params.as_ptr() as *const OSSL_PARAM)
}
#[cfg(not(feature = "export"))]
pub(super) use crate::adapters::common::keymgmt_functions::export_forbidden as export;

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
    let _provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());
    let selection: Selection = handleResult!((selection as u32).try_into());

    if selection.intersects(Selection::KEYPAIR) {
        return HANDLED_KEY_TYPES.as_ptr();
    }
    ERROR_RET
}

#[cfg(feature = "export")]
#[named]
pub(super) unsafe extern "C" fn export_types_ex(
    vprovctx: *mut c_void,
    _selection: c_int,
) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };
    todo!("return a constant array of descriptor OSSL_PARAM(3) for data indicated by selection, that the OSSL_FUNC_keymgmt_export() callback can expect to receive")
}
#[cfg(not(feature = "export"))]
pub(super) use crate::adapters::common::keymgmt_functions::export_types_ex_forbidden as export_types_ex;

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
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
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
            //const BITS: c_int = 8 * (PUBKEY_LEN as c_int);
            //let _ = handleResult!(p.set(BITS));
            let _ = handleResult!(p.set(super::SECURITY_BITS as c_int));
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
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
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
    let _keydata: &mut KeyPair = handleResult!(vkeydata.try_into());

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
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
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

    return std::ptr::from_ref(keypair).cast_mut() as *mut c_void;
}

// based on OpenSSL 3.5's crypto/ml_dsa/ml_dsa_key.c:ossl_ml_dsa_key_equal()
// (and we can't just call it "match", because that's a Rust keyword)
#[named]
pub(super) unsafe extern "C" fn match_(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let keypair1 = handleResult!(<&KeyPair>::try_from(keydata1 as *mut c_void));
    let keypair2 = handleResult!(<&KeyPair>::try_from(keydata2 as *mut c_void));
    let mut key_checked = false;

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR as c_int) != 0 {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int) != 0 {
            if keypair1.public != keypair2.public {
                return ERROR_RET;
            }
            key_checked = true;
        }
        if !key_checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int) != 0 {
            if keypair1.private != keypair2.private {
                return ERROR_RET;
            }
            key_checked = true;
        }
        return key_checked as c_int;
    }

    return 1;
}

pub(super) mod asn_definitions {
    pub use crate::asn_definitions::x509_ml_dsa_2025 as defns;

    pub use defns::MLDSA87PrivateKey as PrivateKey;
    pub use defns::MLDSA87PublicKey as PublicKey;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCTX<'a> {
        provctx: ProviderInstance<'a>,
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

        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");

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

    #[test]
    fn const_sanity_assertions() {
        crate::tests::common::setup().expect("Failed to initialize test setup");

        // Compare against https://github.com/openssl/openssl/blob/openssl-3.5/crypto/ml_dsa/ml_dsa_params.c#L61-L76
        assert_eq!(PUBKEY_LEN, 2592);
        assert_eq!(SECRETKEY_LEN, 4896);
        assert_eq!(SIGNATURE_LEN, 4627);

        // Compare against https://github.com/openssl/openssl/blob/openssl-3.5/crypto/ml_dsa/ml_dsa_params.c#L64
        assert_eq!(SECURITY_BITS, 256);
    }
}

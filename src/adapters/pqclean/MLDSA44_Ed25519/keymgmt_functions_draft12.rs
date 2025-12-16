#![allow(unreachable_code)]

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
use sha2::{Digest, Sha512};
use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
};

use ed25519_dalek as trad_backend_module;
use pqcrypto_mldsa::mldsa44 as pq_backend_module;

type PQPublicKey = pq_backend_module::PublicKey;
type PQPrivateKey = pq_backend_module::SecretKey;
type TPublicKey = trad_backend_module::VerifyingKey;
type TPrivateKey = trad_backend_module::SecretKey;

use super::OurError as KMGMTError;
type OurResult<T> = anyhow::Result<T, KMGMTError>;

use super::signature::{Signature, SignatureBytes, SignatureEncoding};

pub(crate) const PUBKEY_LEN: usize = PublicKey::byte_len();
pub(crate) const SECRETKEY_LEN: usize = PrivateKey::byte_len();
pub(crate) const SIGNATURE_LEN: usize = PrivateKey::signature_bytes();

// The wrapped key from the pqcrypto crate has to be public, or else we can't access it to use it
// with the pqcrypto sign and verify functions.
#[derive(PartialEq)]
pub struct PublicKey {
    pq_public_key: PQPublicKey,
    trad_public_key: TPublicKey,
}

#[derive(PartialEq)]
pub struct PrivateKey {
    pq_private_key: PQPrivateKey,
    trad_private_key: TPrivateKey,
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("pq_public_key", &"<opaque field>")
            .field("trad_public_key", &self.trad_public_key)
            .finish()
    }
}

impl PublicKey {
    const PQ_PUBLIC_KEY_LEN: usize = pq_backend_module::public_key_bytes();
    const T_PUBLIC_KEY_LEN: usize = trad_backend_module::PUBLIC_KEY_LENGTH;
    const PQ_SIGNATURE_LEN: usize = pq_backend_module::signature_bytes();
    const T_SIGNATURE_LEN: usize = trad_backend_module::SIGNATURE_LENGTH;

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        if bytes.len() != Self::byte_len() {
            return Err(anyhow!(
                "Public key should be {:?} bytes (got {:?})",
                Self::byte_len(),
                bytes.len()
            ));
        }

        // if we're here, then the length is correct, and we can safely split_at() and expect()
        let (pq_bytes, trad_bytes) = bytes.split_at(Self::PQ_PUBLIC_KEY_LEN);
        let pq_bytes: &[u8; Self::PQ_PUBLIC_KEY_LEN] =
            pq_bytes.try_into().expect("slice has unexpected size");
        let trad_bytes: &[u8; Self::T_PUBLIC_KEY_LEN] =
            trad_bytes.try_into().expect("slice has unexpected size");

        let pq_public_key =
            <pq_backend_module::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
                pq_bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::PublicKey::from_bytes (MLDSA44) returned {:?}",
                    e
                )
            })?;
        let trad_public_key =
            trad_backend_module::VerifyingKey::from_bytes(trad_bytes).map_err(|e| {
                anyhow!(
                    "trad_backend_module::VerifyingKey::from_bytes (Ed25519) returned {:?}",
                    e
                )
            })?;
        Ok(Self {
            pq_public_key,
            trad_public_key,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let Self {
            pq_public_key,
            trad_public_key,
        } = self;
        let mut bytes =
            <pq_backend_module::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(
                pq_public_key,
            )
            .to_vec();
        bytes.extend(trad_public_key.as_bytes());
        bytes
    }

    pub const fn byte_len() -> usize {
        Self::PQ_PUBLIC_KEY_LEN + Self::T_PUBLIC_KEY_LEN
    }

    pub const fn signature_bytes() -> usize {
        PrivateKey::signature_bytes()
    }

    #[named]
    pub fn from_DER(pk_der_bytes: &[u8]) -> OurResult<Self> {
        trace!(target: log_target!(), "{}", "Called!");

        use asn_definitions::PublicKey as ASNPublicKey;

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

// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-12#name-prefix-label-and-ctx
const PREFIX: &[u8] = "CompositeAlgorithmSignatures2025".as_bytes();
const LABEL: &[u8] = "COMPSIG-MLDSA44-Ed25519-SHA512".as_bytes();

// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-12#name-verify
// There's no way to pass additional context info (`ctx` in the linked spec) into this Verifier
// trait's verify function, so we take `ctx` to be the empty string.
impl Verifier<Signature> for PublicKey {
    #[named]
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), forge::crypto::signature::Error> {
        // get at the public keys
        let Self {
            pq_public_key,
            trad_public_key,
        } = self;

        // separate the parts of the signature
        let sig = sig.to_bytes();
        let sig = sig.as_ref();
        if sig.len() != SIGNATURE_LEN {
            error!(target: log_target!(), "Signature should be {SIGNATURE_LEN:} bytes (got {})", sig.len());
            return Err(forge::crypto::signature::Error::from_source(
                VerificationError::GenericVerificationError,
            ));
        }
        // if we get here, we know we have the right number of bytes, so these calls to split_at()
        // and expect() won't panic
        let (pq_sig, trad_sig) = sig.split_at(Self::PQ_SIGNATURE_LEN);
        let pq_sig: &[u8; Self::PQ_SIGNATURE_LEN] = pq_sig.try_into().expect("Unexpected length");
        let trad_sig: &[u8; Self::T_SIGNATURE_LEN] =
            trad_sig.try_into().expect("Unexpected length");

        // M' :=  Prefix || Domain || len(ctx) || ctx || r || PH( M )
        // (here M is our `msg` argument)
        let msg_hash = Sha512::digest(msg);
        let mut M_prime = PREFIX.to_vec();
        M_prime.extend_from_slice(LABEL);
        M_prime.push(0); // len(ctx) is 0, since ctx is the empty string (see comment at top of impl)
        M_prime.extend(msg_hash);

        // verify with ML-DSA
        use pqcrypto_traits::sign::DetachedSignature;
        let pq_sig = pq_backend_module::DetachedSignature::from_bytes(pq_sig).map_err(|e| {
            error!(target: log_target!(), "Error when verifying PQ signature: {e:?}");
            forge::crypto::signature::Error::from_source(
                VerificationError::GenericVerificationError,
            )
        })?;
        pq_backend_module::verify_detached_signature_ctx(
            &pq_sig,
            M_prime.as_slice(),
            LABEL,
            pq_public_key,
        )
        .map_err(map_PQError_into_VerificationError)
        .map_err(forge::crypto::signature::Error::from_source)?;

        // verify with Ed25519
        let trad_sig = trad_backend_module::Signature::from_bytes(trad_sig);
        trad_public_key
            .verify_strict(M_prime.as_slice(), &trad_sig)
            // this backend uses an opaque error type, so no need for a separate fn with a match arm
            .map_err(|e| {
                error!(target: log_target!(), "Error when verifying traditional signature: {e:?}");
                VerificationError::GenericVerificationError
            })
            .map_err(forge::crypto::signature::Error::from_source)?;

        // if we got here, both verifications passed
        Ok(())
    }
}

#[named]
fn map_PQError_into_VerificationError(
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
    const PQ_PRIVATE_KEY_LEN: usize = pq_backend_module::secret_key_bytes();
    const T_PRIVATE_KEY_LEN: usize = trad_backend_module::SECRET_KEY_LENGTH;
    const PQ_SIGNATURE_LEN: usize = PublicKey::PQ_SIGNATURE_LEN;
    const T_SIGNATURE_LEN: usize = PublicKey::T_SIGNATURE_LEN;

    pub fn encode(&self) -> Vec<u8> {
        let Self {
            pq_private_key,
            trad_private_key,
        } = self;
        let mut bytes =
            <pq_backend_module::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(
                pq_private_key,
            )
            .to_vec();
        bytes.extend(trad_private_key);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KMGMTError> {
        let (pq_bytes, trad_bytes) = bytes
            .split_at_checked(pq_backend_module::secret_key_bytes())
            .ok_or_else(|| anyhow!("Unexpected lenght on decode"))?;
        let pq_private_key =
            <pq_backend_module::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(
                pq_bytes,
            )
            .map_err(|e| {
                anyhow!(
                    "pqcrypto_traits::sign::SecretKey::from_bytes (MLDSA44) returned {:?}",
                    e
                )
            })?;
        let trad_private_key = trad_bytes
            .try_into()
            .map_err(|_| anyhow!("Ed25519 secret key should be 32 bytes"))?;
        Ok(Self {
            pq_private_key,
            trad_private_key,
        })
    }

    pub const fn byte_len() -> usize {
        Self::PQ_PRIVATE_KEY_LEN + Self::T_PRIVATE_KEY_LEN
    }

    pub const fn signature_bytes() -> usize {
        Self::PQ_SIGNATURE_LEN + Self::T_SIGNATURE_LEN
    }

    fn derive_PQ_public_key(&self) -> Option<PQPublicKey> {
        super::helpers::derive_public_key(&self.pq_private_key)
    }

    /// Derive a matching public key from this private key
    #[named]
    pub fn derive_public_key(&self) -> Option<PublicKey> {
        trace!(target: log_target!(), "Called");

        let t_sk = &self.trad_private_key;
        let t_sk = trad_backend_module::SigningKey::from_bytes(t_sk);
        let t_pk = t_sk.verifying_key();

        let pq_pk = match self.derive_PQ_public_key() {
            Some(pk) => pk,
            None => {
                return None;
            }
        };

        let pk = PublicKey {
            pq_public_key: pq_pk,
            trad_public_key: t_pk,
        };
        Some(pk)
    }

    #[named]
    pub fn from_DER(sk_der_bytes: &[u8]) -> OurResult<(Self, Option<PublicKey>)> {
        use asn_definitions::PrivateKey as ASNPrivateKey;
        trace!(target: log_target!(), "Called");

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
        trace!(target: log_target!(), "Called");
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

// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-06#name-sign
// Just like with the Verifier above, there's no way to pass additional context info (`ctx` in the
// linked spec) into this Signer trait's try_sign function, so we take `ctx` to be the empty string.
impl Signer<Signature> for PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, forge::crypto::signature::Error> {
        // M' :=  Prefix || Label || len(ctx) || ctx || PH( M )
        // (here M is our `msg` argument)
        let msg_hash = Sha512::digest(msg);
        let mut M_prime = PREFIX.to_vec();
        M_prime.extend_from_slice(LABEL);
        M_prime.push(0); // len(ctx) is 0, since ctx is the empty string (see comment above)
        M_prime.extend(msg_hash);

        // get at the private keys
        let Self {
            pq_private_key,
            trad_private_key,
        } = self;

        // sign with ML-DSA
        // (the Label being used as the `ctx` here refers to the underlying ML-DSA
        // signature operation, and has nothing to do with the empty `ctx` string from the spec)
        let pq_signature = pq_backend_module::detached_sign_ctx(&M_prime, LABEL, pq_private_key);

        // sign with Ed25519
        let trad_signature =
            trad_backend_module::SigningKey::from_bytes(trad_private_key).sign(&M_prime);

        // build the result
        let mut signature = pq_signature.as_bytes().to_vec();
        signature.extend_from_slice(&trad_signature.to_bytes());

        Signature::try_from(signature.as_slice())
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
        let (pq_public_key, pq_private_key) = pq_backend_module::keypair();

        // Similarly, it seems weird that this can't fail. Hopefully a different layer can handle it
        // if something goes wrong here.
        let trad_keypair = trad_backend_module::SigningKey::generate(provctx.get_rng());
        let trad_private_key = trad_keypair.to_bytes();
        let trad_public_key = trad_keypair.verifying_key();

        Ok(KeyPair {
            private: Some(PrivateKey {
                pq_private_key,
                trad_private_key,
            }),
            public: Some(PublicKey {
                pq_public_key,
                trad_public_key,
            }),
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
    debug!(target: log_target!(), "keypair: {keypair:#?}");

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

    pub use defns::MLDSA44PrivateKey as PrivateKey;
    pub use defns::MLDSA44PublicKey as PublicKey;
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

        // Compare against https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-12#name-maximum-key-and-signature-s
        // except the SECRETKEY_LEN, which is 64 in that table because that document uses the
        // assumption that only the seed of the ML-DSA secret key should be stored
        assert_eq!(PUBKEY_LEN, 1344);
        assert_eq!(SECRETKEY_LEN, 2592);
        assert_eq!(SIGNATURE_LEN, 2484);

        assert_eq!(SECURITY_BITS, 128);
    }
}

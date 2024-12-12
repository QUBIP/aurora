use super::*;
use crate::adapters::libcrux::X25519MLKEM768::keymgmt_functions::{KeyPair, PrivateKey, PublicKey};
use anyhow::anyhow;
use bindings::ossl_param_st;
use libc::{c_int, c_uchar, c_void};

#[expect(dead_code)]
struct KemContext<'a> {
    private_key: Option<&'a PrivateKey>,
    public_key: Option<&'a PublicKey>,
    provctx: *mut c_void,
}

impl<'a> From<*mut core::ffi::c_void> for &mut KemContext<'a> {
    #[named]
    fn from(vctx: *mut core::ffi::c_void) -> Self {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> From<*mut core::ffi::c_void> for &mut KemContext<'a>"
        );
        let ctxp = vctx as *mut KemContext;
        if ctxp.is_null() {
            panic!("vctx was null");
        }
        unsafe { &mut *ctxp }
    }
}

impl<'a> From<*mut core::ffi::c_void> for &KemContext<'a> {
    fn from(vctx: *mut core::ffi::c_void) -> Self {
        let ctxp: &mut KemContext = vctx.into();
        ctxp
    }
}

#[named]
pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    let kem_ctx = Box::new(KemContext {
        private_key: None,
        public_key: None,
        provctx: vprovctx,
    });
    Box::into_raw(kem_ctx).cast()
}

#[named]
pub(super) extern "C" fn freectx(vkemctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    if !vkemctx.is_null() {
        let kem_ctx: Box<KemContext> = unsafe { Box::from_raw(vkemctx.cast()) };
        drop(kem_ctx);
    }
}

impl<'a> KemContext<'a> {
    pub fn set_peer_pubkey(&mut self, peerkey: &'a PublicKey) -> anyhow::Result<()> {
        self.public_key = Some(peerkey);
        Ok(())
    }

    pub fn set_peer_keypair(&mut self, peerkeypair: &'a KeyPair) -> anyhow::Result<()> {
        match &peerkeypair.public {
            Some(pubkey) => self.set_peer_pubkey(pubkey),
            None => Err(anyhow!("Missing public key")),
        }
    }
}

#[named]
pub(super) extern "C" fn encapsulate_init(
    vkemctx: *mut c_void,
    vprovkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let kemctx: &mut KemContext<'_> = vkemctx.try_into().unwrap();
    let keypair: &mut KeyPair = vprovkey.try_into().unwrap();

    match kemctx.set_peer_keypair(keypair) {
        Ok(_) => 1,
        Err(e) => {
            error!(target: log_target!(), "set_peer_keypair() failed with {}", e);
            0
        }
    }
}

#[named]
pub(super) extern "C" fn decapsulate_init(
    vkemctx: *mut c_void,
    provkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let kem_ctx = unsafe { &mut *(vkemctx as *mut KemContext) };

    let keypair: &mut KeyPair = provkey.try_into().unwrap();

    if keypair.private.is_none() {
        return 0;
    }

    kem_ctx.private_key = keypair.private.as_ref();

    1
}

#[named]
pub(super) extern "C" fn encapsulate(
    ctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    secret: *mut c_uchar,
    secretlen: *mut usize,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    if ctx.is_null() {
        error!(target: log_target!(), "Context is null");
        return 0;
    }

    let kem_ctx: &mut KemContext = unsafe { &mut *(ctx as *mut KemContext) };

    let public_key = match kem_ctx.public_key.as_ref() {
        Some(pk) => pk,
        None => {
            error!(target: log_target!(), "No public key in the context");
            return 0;
        }
    };

    let mut rng = rand::rngs::OsRng;

    let (shared_secret, ciphertext) = match public_key.encapsulate(&mut rng) {
        Ok((shared_secret, ciphertext)) => (shared_secret, ciphertext),
        Err(e) => {
            error!(target: log_target!(), "Encapsulation failed: {:?}", e);
            return 0;
        }
    };

    unsafe {
        let encoded_ciphertext = ciphertext.encode();
        std::ptr::copy_nonoverlapping(encoded_ciphertext.as_ptr(), out, encoded_ciphertext.len());
        *outlen = encoded_ciphertext.len();

        let encoded_secret = shared_secret.encode();
        std::ptr::copy_nonoverlapping(encoded_secret.as_ptr(), secret, encoded_secret.len());
        *secretlen = encoded_secret.len();
    }

    1
}

#[named]
pub(super) extern "C" fn decapsulate(
    ctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    in_: *const c_uchar,
    inlen: usize,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let kem_ctx: &mut KemContext = unsafe { &mut *(ctx as *mut KemContext) };

    let private_key = match kem_ctx.private_key.as_ref() {
        Some(pk) => pk,
        None => {
            error!(target: log_target!(), "No private key in the context");
            return 0;
        }
    };

    let ciphertext = unsafe { std::slice::from_raw_parts(in_, inlen) };

    if ciphertext.is_empty() {
        error!(target: log_target!(), "No encapsulated data found");
        return 0;
    }

    let ct =
        match libcrux_kem::Ct::decode(libcrux_kem::Algorithm::X25519MlKem768Draft00, ciphertext) {
            Ok(ct) => ct,
            Err(e) => {
                error!(target: log_target!(), "Failed to decode ciphertext: {:?}", e);
                return 0;
            }
        };

    let shared_secret = match ct.decapsulate(private_key) {
        Ok(secret) => secret.encode(),
        Err(e) => {
            error!(target: log_target!(), "Decapsulation failed: {:?}", e);
            return 0;
        }
    };

    unsafe {
        if out.is_null() {
            *outlen = shared_secret.len();
            trace!(target: log_target!(), "Output buffer is null, returning length: {}", shared_secret.len());
        } else {
            if *outlen < shared_secret.len() {
                error!(target: log_target!(), "Output buffer is too small");
                return 0;
            }
            std::ptr::copy_nonoverlapping(shared_secret.as_ptr(), out, shared_secret.len());
            *outlen = shared_secret.len();
            trace!(target: log_target!(), "Decapsulation successful, output length: {}", shared_secret.len());
        }
    }

    1
}

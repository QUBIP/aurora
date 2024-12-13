use super::*;
use crate::{adapters::libcrux::X25519MLKEM768::keymgmt_functions::KeyPair, handleResult};
use bindings::ossl_param_st;
use kem::Encapsulate;
use libc::{c_int, c_uchar, c_void};
use rand_core::CryptoRngCore;
use super::OurError as KEMError;

#[expect(dead_code)]
struct KemContext<'a> {
    own_keypair: Option<&'a KeyPair<'a>>,
    peer_keypair: Option<&'a KeyPair<'a>>,
    provctx: *mut c_void,
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &mut KemContext<'a> {
    type Error = KEMError;

    #[named]
    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut core::ffi::c_void> for &mut KemContext<'a>"
        );
        let ctxp = vctx as *mut KemContext;
        if ctxp.is_null() {
            return Err(anyhow::anyhow!("vctx was null"));
        }
        Ok(unsafe { &mut *ctxp })
    }
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &KemContext<'a> {
    type Error = KEMError;

    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        let ctxp: &mut KemContext = vctx.try_into()?;
        Ok(ctxp)
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
        own_keypair: None,
        peer_keypair: None,
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

use super::keymgmt_functions::{EncapsulatedKey, SharedSecret};

impl Encapsulate<EncapsulatedKey, SharedSecret> for KemContext<'_> {
    type Error = KEMError;

    #[named]
    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncapsulatedKey, SharedSecret), Self::Error> {
        trace!(target: log_target!(), "Called ");
        match self.peer_keypair {
            Some(pk) => pk.encapsulate(rng),
            None => {
                error!(target: log_target!(), "KemContext is missing a public key");
                Err(anyhow!("Missing public key"))
            }
        }
    }
}

impl KemContext<'_> {
    #[named]
    #[expect(dead_code)]
    fn encapsulate_ex(&self) -> Result<(EncapsulatedKey, SharedSecret), KEMError> {
        trace!(target: log_target!(), "Called ");
        match self.peer_keypair {
            Some(pk) => pk.encapsulate_ex(),
            None => {
                error!(target: log_target!(), "KemContext is missing a public key");
                Err(anyhow!("Missing public key"))
            }
        }
    }
}

impl<'a> KemContext<'a> {
    pub fn set_peer_keypair(&mut self, peerkeypair: &'a KeyPair) -> anyhow::Result<()> {
        match &peerkeypair.public {
            Some(_pubkey) => {
                self.peer_keypair = Some(peerkeypair);
                Ok(())
            }
            None => Err(anyhow!("Missing public key")),
        }
    }

    pub fn set_own_keypair(&mut self, ownkeypair: &'a KeyPair) -> anyhow::Result<()> {
        match &ownkeypair.private {
            Some(_privkey) => {
                self.own_keypair = Some(ownkeypair);
                Ok(())
            }
            None => Err(anyhow!("Missing private key")),
        }
    }
}

#[named]
pub(super) extern "C" fn encapsulate_init(
    vkemctx: *mut c_void,
    vprovkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());
    let keypair: &mut KeyPair = handleResult!(vprovkey.try_into());

    let r = kemctx.set_peer_keypair(keypair).map_or_else(
        |e| {
            error!(target: log_target!(), "set_peer_keypair() failed with {}", e);
            ERROR_RET
        },
        |_ok| 1,
    );

    return r;
}

#[named]
pub(super) extern "C" fn decapsulate_init(
    vkemctx: *mut c_void,
    vprovkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());
    let keypair: &mut KeyPair = handleResult!(vprovkey.try_into());

    match kemctx.set_own_keypair(keypair) {
        Ok(_) => 1,
        Err(e) => {
            error!(target: log_target!(), "Private key not found {}", e);
            return ERROR_RET;
        }
    }
}

#[named]
pub(super) extern "C" fn encapsulate(
    vkemctx: *mut c_void,
    _out: *mut c_uchar,
    _outlen: *mut usize,
    _secret: *mut c_uchar,
    _secretlen: *mut usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let _kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());

    todo!("Use kemctx to decapsulate it, handle errors, properly write the result to `out` (ct) and `secret` (ss)");

    //let (shared_secret, ciphertext) = match public_key.encapsulate(&mut rng) {
    //    Ok((shared_secret, ciphertext)) => (shared_secret, ciphertext),
    //    Err(e) => {
    //        error!(target: log_target!(), "Encapsulation failed: {:?}", e);
    //        return 0;
    //    }
    //};

    //unsafe {
    //    let encoded_ciphertext = ciphertext.encode();
    //    std::ptr::copy_nonoverlapping(encoded_ciphertext.as_ptr(), out, encoded_ciphertext.len());
    //    *outlen = encoded_ciphertext.len();

    //    let encoded_secret = shared_secret.encode();
    //    std::ptr::copy_nonoverlapping(encoded_secret.as_ptr(), secret, encoded_secret.len());
    //    *secretlen = encoded_secret.len();
    //}

    //1
}

#[named]
pub(super) extern "C" fn decapsulate(
    vkemctx: *mut c_void,
    _out: *mut c_uchar,
    _outlen: *mut usize,
    _in_: *const c_uchar,
    _inlen: usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");
    let _kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());

    todo!("Convert `in` in a suitable slice (it's the ciphertext), use kemctx to decapsulate it, handle errors, properly write the result to `out`");

    //let kem_ctx: &mut KemContext = unsafe { &mut *(ctx as *mut KemContext) };

    //let private_key = match kem_ctx.private_key.as_ref() {
    //    Some(pk) => pk,
    //    None => {
    //        error!(target: log_target!(), "No private key in the context");
    //        return 0;
    //    }
    //};

    //let ciphertext = unsafe { std::slice::from_raw_parts(in_, inlen) };

    //if ciphertext.is_empty() {
    //    error!(target: log_target!(), "No encapsulated data found");
    //    return 0;
    //}

    //let ct =
    //    match libcrux_kem::Ct::decode(libcrux_kem::Algorithm::X25519MlKem768Draft00, ciphertext) {
    //        Ok(ct) => ct,
    //        Err(e) => {
    //            error!(target: log_target!(), "Failed to decode ciphertext: {:?}", e);
    //            return 0;
    //        }
    //    };

    //let shared_secret = match ct.decapsulate(private_key) {
    //    Ok(secret) => secret.encode(),
    //    Err(e) => {
    //        error!(target: log_target!(), "Decapsulation failed: {:?}", e);
    //        return 0;
    //    }
    //};

    //unsafe {
    //    if out.is_null() {
    //        *outlen = shared_secret.len();
    //        trace!(target: log_target!(), "Output buffer is null, returning length: {}", shared_secret.len());
    //    } else {
    //        if *outlen < shared_secret.len() {
    //            error!(target: log_target!(), "Output buffer is too small");
    //            return 0;
    //        }
    //        std::ptr::copy_nonoverlapping(shared_secret.as_ptr(), out, shared_secret.len());
    //        *outlen = shared_secret.len();
    //        trace!(target: log_target!(), "Decapsulation successful, output length: {}", shared_secret.len());
    //    }
    //}

    //1
}

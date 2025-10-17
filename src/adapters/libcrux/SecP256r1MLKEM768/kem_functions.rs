use super::keymgmt_functions::KeyPair;
use super::OurError as KEMError;
use super::*;
use bindings::OSSL_PARAM;
use kem::{Decapsulate, Encapsulate};
use libc::{c_int, c_uchar, c_void};
use rand_core::CryptoRngCore;

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
    let _provctx: &ProviderInstance<'_> = match vprovctx.try_into() {
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
            Some(pkp) => pkp.encapsulate(rng),
            None => {
                error!(target: log_target!(), "KemContext is missing a public key");
                Err(anyhow!("Missing public key"))
            }
        }
    }
}

impl Decapsulate<EncapsulatedKey, SharedSecret> for KemContext<'_> {
    type Error = KEMError;

    #[named]
    fn decapsulate(&self, encapsulated_key: &EncapsulatedKey) -> Result<SharedSecret, Self::Error> {
        trace!(target: log_target!(), "Called ");
        match self.own_keypair {
            Some(okp) => okp.decapsulate(encapsulated_key),
            None => {
                error!(target: log_target!(), "KemContext is missing a private key");
                Err(anyhow!("Missing private key"))
            }
        }
    }
}

impl KemContext<'_> {
    #[named]
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
    _params: *mut OSSL_PARAM,
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
    _params: *mut OSSL_PARAM,
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
fn u8_slice_try_from_raw_parts<'a>(p: *const c_uchar, len: usize) -> Result<&'a [u8], KEMError> {
    trace!(target: log_target!(), "{}", "Called!");
    if p.is_null() {
        return Err(anyhow!("Passed a null pointer"));
    }
    if len == 0 {
        return Err(anyhow!("Passed zero lenght"));
    }
    let r = unsafe { std::slice::from_raw_parts(p, len) };
    Ok(r)
}

#[named]
fn u8_mut_slice_try_from_raw_parts<'a>(
    p: *mut c_uchar,
    lenp: *mut usize,
) -> Result<&'a mut [u8], KEMError> {
    trace!(target: log_target!(), "{}", "Called!");
    if p.is_null() || lenp.is_null() {
        return Err(anyhow!("Passed a null pointer"));
    }
    let len = unsafe { *lenp };
    if len == 0 {
        return Err(anyhow!("Passed zero lenght"));
    }
    let r = unsafe { std::slice::from_raw_parts_mut(p, len) };
    Ok(r)
}

#[named]
pub(super) extern "C" fn decapsulate(
    vkemctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    inp: *const c_uchar,
    inlen: usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());
    if out.is_null() && !outlen.is_null() {
        let expected_ss_len = match kemctx.own_keypair {
            Some(kp) => handleResult!(kp.expected_ss_size()),
            None => todo!(),
        };
        unsafe {
            *outlen = expected_ss_len;
        }
        trace!(target: log_target!(), "Size of output ss buffer should be {}", expected_ss_len);
        return 1;
    }
    let ct_in_slice = handleResult!(u8_slice_try_from_raw_parts(inp, inlen));
    let ct_vec = ct_in_slice.to_vec();
    let ss_out = handleResult!(u8_mut_slice_try_from_raw_parts(out, outlen));

    trace!(target: log_target!(),"{}", "Calling kemctx.decapsulate");
    let ss = handleResult!(kemctx.decapsulate(&ct_vec));

    trace!(target: log_target!(), "{}", "Copying to output slice");
    ss_out.copy_from_slice(ss.as_slice());

    trace!(target: log_target!(), "{}", "Returning successfully!");
    return 1;
}

#[named]
pub(super) extern "C" fn encapsulate(
    vkemctx: *mut c_void,
    out: *mut c_uchar,
    outlen: *mut usize,
    secret: *mut c_uchar,
    secretlen: *mut usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    let kemctx: &mut KemContext<'_> = handleResult!(vkemctx.try_into());
    if out.is_null() && !outlen.is_null() && !secretlen.is_null() {
        let expected_ct_len = match kemctx.peer_keypair {
            Some(kp) => handleResult!(kp.expected_ct_size()),
            None => todo!(),
        };
        let expected_ss_len = match kemctx.peer_keypair {
            Some(kp) => handleResult!(kp.expected_ss_size()),
            None => todo!(),
        };

        unsafe {
            *outlen = expected_ct_len;
            *secretlen = expected_ss_len;
        }
        trace!(target: log_target!(), "Size of output ct buffer should be {}", expected_ct_len);
        trace!(target: log_target!(), "Size of output ss buffer should be {}", expected_ss_len);
        return 1;
    }

    let ct_out = handleResult!(u8_mut_slice_try_from_raw_parts(out, outlen));
    let ss_out = handleResult!(u8_mut_slice_try_from_raw_parts(secret, secretlen));

    let (ct, ss) = handleResult!(kemctx.encapsulate_ex());

    ct_out.copy_from_slice(ct.as_slice());
    ss_out.copy_from_slice(ss.as_slice());

    trace!(target: log_target!(), "{}", "Returning successfully!");
    return 1;
}

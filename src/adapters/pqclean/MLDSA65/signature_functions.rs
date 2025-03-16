use super::keymgmt_functions::KeyPair;
use super::OurError as SignatureError;
use super::*;
use anyhow::bail;
use bindings::OSSL_PARAM;
use libc::{c_int, c_uchar, c_void};
use pqcrypto_traits::sign::{DetachedSignature, SignedMessage};

type OurResult<T> = anyhow::Result<T, SignatureError>;

pub(crate) const SIGNATURE_LENGTH: usize = 3309;

#[expect(dead_code)]
struct SignatureContext<'a> {
    keypair: Option<&'a KeyPair<'a>>,
    signed_message: Option<&'a pqcrypto_mldsa::mldsa65::SignedMessage>,
    provctx: *mut c_void,
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &mut SignatureContext<'a> {
    type Error = SignatureError;

    #[named]
    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl<'a> TryFrom<*mut core::ffi::c_void> for &mut SignatureContext<'a>"
        );
        let ctxp = vctx as *mut SignatureContext;
        if ctxp.is_null() {
            return Err(anyhow::anyhow!("vctx was null"));
        }
        Ok(unsafe { &mut *ctxp })
    }
}

impl<'a> TryFrom<*mut core::ffi::c_void> for &SignatureContext<'a> {
    type Error = SignatureError;

    fn try_from(vctx: *mut core::ffi::c_void) -> Result<Self, Self::Error> {
        let ctxp: &mut SignatureContext = vctx.try_into()?;
        Ok(ctxp)
    }
}

impl<'a> SignatureContext<'a> {
    #[cfg(test)]
    pub fn new(provctx: &OpenSSLProvider) -> Self {
        SignatureContext {
            keypair: None,
            signed_message: None,
            // this looks awful, but it's just for testing
            provctx: provctx as *const OpenSSLProvider as *mut c_void,
        }
    }

    pub fn set_keypair(&mut self, keypair: &'a KeyPair) -> anyhow::Result<()> {
        match (&keypair.public, &keypair.private) {
            (None, None) => Err(anyhow!("Empty keypair")),
            _ => {
                self.keypair = Some(keypair);
                Ok(())
            }
        }
    }
}

#[named]
pub(super) extern "C" fn newctx(vprovctx: *mut c_void, propq: *const c_uchar) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    warn!("Ignoring *propq");
    let _ = propq;

    let sig_ctx = Box::new(SignatureContext {
        keypair: None,
        signed_message: None,
        provctx: vprovctx,
    });
    Box::into_raw(sig_ctx).cast()
}

#[named]
pub(super) extern "C" fn freectx(vsigctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");
    if !vsigctx.is_null() {
        let sig_ctx: Box<SignatureContext> = unsafe { Box::from_raw(vsigctx.cast()) };
        drop(sig_ctx);
    }
}

impl<'a> SignatureContext<'a> {
    pub fn sign_init(&mut self, keypair: &'a KeyPair) -> OurResult<()> {
        if keypair.private.is_some() {
            self.set_keypair(keypair)
        } else {
            Err(anyhow!("sign_init() requires secret key"))
        }
    }

    pub fn sign(&mut self, msg: &[u8]) -> Result<pqcrypto_mldsa::mldsa65::SignedMessage, &str> {
        if let Some(keypair) = self.keypair {
            if let Some(sk) = &keypair.private {
                let signed_msg = pqcrypto_mldsa::mldsa65::sign(msg, &sk.0);
                return Ok(signed_msg);
            }
        }
        return Err("Unable to sign message (likely cause: no private key)");
    }

    pub fn verify_init(&mut self, keypair: &'a KeyPair) -> OurResult<()> {
        if keypair.public.is_some() {
            self.set_keypair(keypair)
        } else {
            Err(anyhow!("verify_init() requires public key"))
        }
    }

    pub fn verify(&mut self, sig: &[u8], msg: &[u8]) -> anyhow::Result<()> {
        if let Some(keypair) = self.keypair {
            if let Some(pk) = &keypair.public {
                let sig = pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(sig)?;
                let res = pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, msg, &pk.0)?;
                return Ok(res);
            } else {
                bail!("No public key available for verification");
            }
        }
        bail!("Unable to verify message")
    }
}

#[named]
pub(super) extern "C" fn sign_init(
    vsigctx: *mut c_void,
    vprovkey: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;
    trace!(target: log_target!(), "{}", "Called!");

    let _ = params;
    warn!("Ignoring *params");

    let sig_ctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());
    let keypair: &mut KeyPair = handleResult!(vprovkey.try_into());

    let r = sig_ctx.sign_init(keypair).map_or_else(
        |e| {
            error!(target: log_target!(), "sign_init() failed with {:?}", e);
            ERROR_RET
        },
        |_ok| SUCCESS_RET,
    );

    return r;
}

#[named]
pub(super) extern "C" fn sign(
    vsigctx: *mut c_void,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;
    trace!(target: log_target!(), "{}", "Called!");

    let sig_ctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());

    // if sig is null, this is just a request for the maximum sig length
    if sig.is_null() {
        // write the max byte length of a signature to *siglen
        unsafe { siglen.as_mut() }.map(|p| {
            *p = SIGNATURE_LENGTH;
        });
        return SUCCESS_RET;
    }

    // otherwise, we actually have something to sign, so let's sign it
    let tbs_slice = handleResult!(u8_slice_try_from_raw_parts(tbs, tbslen));
    match sig_ctx.sign(tbs_slice) {
        Ok(signed_msg) => {
            // check that the signature fits in sigsize bytes
            // (this check could be moved before `let tbs_slice = ...`, if we wanted...)
            let nr_bytes = signed_msg.len();
            if nr_bytes > sigsize {
                // error because our signature is longer than permitted :(
                error!("signature of {} bytes doesn't fit in {}", nr_bytes, sigsize);
                return ERROR_RET;
            } else {
                // write the signature to the provided memory address
                unsafe {
                    std::ptr::copy(signed_msg.as_bytes().as_ptr(), sig, nr_bytes);
                }
                return SUCCESS_RET;
            }
        }
        Err(e) => {
            error!(target: log_target!(), "sign() failed with {:?}", e);
            ERROR_RET
        }
    }
}

#[named]
pub(super) extern "C" fn verify_init(
    vsigctx: *mut c_void,
    vprovkey: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;
    trace!(target: log_target!(), "{}", "Called!");

    let _ = params;
    warn!("Ignoring *params");

    let sig_ctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());
    let keypair: &mut KeyPair = handleResult!(vprovkey.try_into());

    let r = sig_ctx.verify_init(keypair).map_or_else(
        |e| {
            error!(target: log_target!(), "verify_init() failed with {:?}", e);
            ERROR_RET
        },
        |_ok| SUCCESS_RET,
    );

    return r;
}

#[named]
pub(super) extern "C" fn verify(
    vsigctx: *mut c_void,
    sig: *const c_uchar,
    siglen: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;
    trace!(target: log_target!(), "{}", "Called!");

    let sig_ctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());

    if sig.is_null() {
        error!("null signature");
        return ERROR_RET;
    }

    if tbs.is_null() {
        error!("null message");
        return ERROR_RET;
    }

    let sig_slice = handleResult!(u8_slice_try_from_raw_parts(sig, siglen));
    let msg_slice = handleResult!(u8_slice_try_from_raw_parts(tbs, tbslen));
    match sig_ctx.verify(sig_slice, msg_slice) {
        Ok(_) => {
            return SUCCESS_RET;
        }
        Err(e) => {
            error!(target: log_target!(), "verify() failed with {:?}", e);
            ERROR_RET
        }
    }
}

#[named]
fn u8_slice_try_from_raw_parts<'a>(
    p: *const c_uchar,
    len: usize,
) -> Result<&'a [u8], SignatureError> {
    trace!(target: log_target!(), "{}", "Called!");
    if p.is_null() {
        return Err(anyhow!("Passed a null pointer"));
    }
    if len == 0 {
        return Err(anyhow!("Passed zero length"));
    }
    let r = unsafe { std::slice::from_raw_parts(p, len) };
    Ok(r)
}

#[named]
fn u8_mut_slice_try_from_raw_parts<'a>(
    p: *mut c_uchar,
    lenp: *mut usize,
) -> Result<&'a mut [u8], SignatureError> {
    trace!(target: log_target!(), "{}", "Called!");
    if p.is_null() || lenp.is_null() {
        return Err(anyhow!("Passed a null pointer"));
    }
    let len = unsafe { *lenp };
    if len == 0 {
        return Err(anyhow!("Passed zero length"));
    }
    let r = unsafe { std::slice::from_raw_parts_mut(p, len) };
    Ok(r)
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
    fn test_sign() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate a keypair
        let keypair = KeyPair::generate_new(&provctx);
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signed_msg = sigctx.sign(&msg).unwrap();
        assert_eq!(signed_msg.len(), SIGNATURE_LENGTH + msg.len());
        // the sig is prepended to the msg, so we compare the last bytes (here the last 5)
        assert_eq!(signed_msg.as_bytes()[signed_msg.len() - msg.len()..], msg);
        // (this test succeeds if we've gotten this far without anything exploding)
    }

    #[test]
    fn test_sign_and_verify_success() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx);
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signed_msg = sigctx.sign(&msg).unwrap();
        assert_eq!(signed_msg.len(), SIGNATURE_LENGTH + msg.len());
        // the sig is prepended to the msg, so we compare the last bytes (here the last 5)
        assert_eq!(signed_msg.as_bytes()[signed_msg.len() - msg.len()..], msg);
        // verify the signature
        sigctx.verify_init(&keypair).unwrap();
        let detached_sig = &signed_msg.as_bytes()[..SIGNATURE_LENGTH];
        assert!(sigctx.verify(detached_sig, &msg).is_ok());
    }

    #[test]
    fn test_sign_and_verify_wrong_key_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx);
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signed_msg = sigctx.sign(&msg).unwrap();
        let detached_sig = &signed_msg.as_bytes()[..SIGNATURE_LENGTH];
        // generate another keypair
        let other_keypair = KeyPair::generate_new(&provctx);
        // confirm that verification with the new key fails
        sigctx.verify_init(&other_keypair).unwrap();
        assert!(sigctx.verify(detached_sig, &msg).is_err());
    }

    #[test]
    fn test_sign_and_verify_tampered_sig_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx);
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signed_msg = sigctx.sign(&msg).unwrap();
        let mut detached_sig = [0; SIGNATURE_LENGTH];
        detached_sig.copy_from_slice(&signed_msg.as_bytes()[..SIGNATURE_LENGTH]);
        // flip a bit in the signature
        detached_sig[0] = std::ops::BitXor::bitxor(detached_sig[0], 1u8);
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&detached_sig, &msg).is_err());
    }

    #[test]
    fn test_sign_and_verify_tampered_msg_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx);
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signed_msg = sigctx.sign(&msg).unwrap();
        let detached_sig = &signed_msg.as_bytes()[..SIGNATURE_LENGTH];
        // construct a different message of the same length
        let other_msg: [u8; 5] = [1, 2, 3, 8, 5];
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&detached_sig, &other_msg).is_err());
        // construct a longer message with the same initial contents
        let other_msg: [u8; 6] = [1, 2, 3, 4, 5, 6];
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&detached_sig, &other_msg).is_err());
    }
}

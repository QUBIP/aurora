use std::error::Error;

use super::keymgmt_functions::KeyPair;
use super::signature::*;
use super::OurError as SignatureError;
use super::*;
use bindings::{OSSL_PARAM, OSSL_SIGNATURE_PARAM_ALGORITHM_ID};
use forge::operations::signature::VerificationError;
use forge::osslparams::OSSLParam;
use libc::{c_char, c_int, c_uchar, c_void};

type OurResult<T> = anyhow::Result<T, SignatureError>;

pub(crate) const SIGNATURE_LEN: usize = super::keymgmt_functions::SIGNATURE_LEN;

#[expect(dead_code)]
struct SignatureContext<'a> {
    keypair: Option<&'a KeyPair<'a>>,
    provctx: &'a OpenSSLProvider<'a>,
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
    pub fn new(provctx: &'a OpenSSLProvider) -> Self {
        SignatureContext {
            keypair: None,
            provctx,
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
pub(super) extern "C" fn newctx(vprovctx: *mut c_void, _propq: *const c_uchar) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let provctx: &OpenSSLProvider<'_> = match vprovctx.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "{}", e);
            return ERROR_RET;
        }
    };

    warn!(target: log_target!(), "Ignoring *propq");
    let _ = _propq;

    let sig_ctx = Box::new(SignatureContext {
        keypair: None,
        provctx,
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
            Err(anyhow!("sign_init() requires a secret key"))
        }
    }

    #[named]
    pub fn verify_init(&mut self, keypair: &'a KeyPair) -> OurResult<()> {
        trace!(target: log_target!(), "🧾 Called!");
        if keypair.public.is_some() {
            self.set_keypair(keypair)
        } else {
            Err(anyhow!("verify_init() requires public key"))
        }
    }
}

impl<'a> Signer<Signature> for SignatureContext<'a> {
    #[named]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        trace!(target: log_target!(), "🧾 Called!");
        let keypair = self
            .keypair
            .ok_or_else(|| anyhow!("Signature context is badly initialized: missing keypair"))
            .map_err(signature::Error::from_source)?;
        keypair.try_sign(msg)
    }
}

impl<'a> Verifier<Signature> for SignatureContext<'a> {
    #[named]
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), signature::Error> {
        trace!(target: log_target!(), "🧾 Called!");

        let keypair = self
            .keypair
            .ok_or_else(|| anyhow!("Signature contest is badly initialized: missing keypair"))
            .map_err(|e| {
                error!("{e:#}");
                VerificationError::GenericVerificationError
            })
            .map_err(super::signature::Error::from_source)?;

        keypair.verify(msg, sig)
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
            *p = SIGNATURE_LEN;
        });
        return SUCCESS_RET;
    }
    if sigsize < SIGNATURE_LEN {
        error! {target: log_target!(), "the output buffer for the signature is too small ({sigsize} < {SIGNATURE_LEN})"};
        return ERROR_RET;
    }
    let sigout = handleResult!(u8_mut_slice_try_from_raw_parts(sig, siglen));

    // otherwise, we actually have something to sign, so let's sign it
    let tbs_slice = handleResult!(u8_slice_try_from_raw_parts(tbs, tbslen));
    match sig_ctx.try_sign(tbs_slice) {
        Ok(signature) => {
            let signature = signature.to_bytes();
            let signature = signature.as_ref();
            if sigout.len() < signature.len() {
                error! {target: log_target!(), "the generated signature does not fit within the provided buffer ({} < {})", sigout.len(), signature.len()};
                return ERROR_RET;
            }
            sigout.clone_from_slice(signature);
            return SUCCESS_RET;
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
    let sig = handleResult!(Signature::try_from(sig_slice));
    let msg_slice = handleResult!(u8_slice_try_from_raw_parts(tbs, tbslen));
    match sig_ctx.verify(msg_slice, &sig) {
        Ok(_) => {
            return SUCCESS_RET;
        }
        Err(e) => {
            error!(target: log_target!(), "verify() failed with {e:?}");
            ERROR_RET
        }
    }
}

#[named]
pub(super) unsafe extern "C" fn gettable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OSSL_PARAM {
    trace!(target: log_target!(), "{}", "Called!");

    static LIST: &[CONST_OSSL_PARAM] = &[
        OSSLParam::new_const_octetstring(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, None),
        CONST_OSSL_PARAM::END,
    ];

    std::ptr::from_ref(&LIST[0])
}

#[named]
pub(super) unsafe extern "C" fn get_ctx_params(
    _ctx: *mut c_void,
    params: *mut OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS: c_int = 1;

    trace!(target: log_target!(), "{}", "Called!");

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

        if key == OSSL_SIGNATURE_PARAM_ALGORITHM_ID {
            let _ = p.set(super::ALGORITHM_ID_DER.as_slice());
        } else {
            debug!(target: log_target!(), "Ignoring param {:?}", key);
        }
    }

    SUCCESS
}

pub(super) unsafe extern "C" fn settable_ctx_params(
    _ctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OSSL_PARAM {
    todo!();
}

pub(super) unsafe extern "C" fn set_ctx_params(
    _ctx: *mut c_void,
    _params: *const OSSL_PARAM,
) -> c_int {
    todo!();
}

#[named]
pub(super) unsafe extern "C" fn digest_verify_init(
    vsigctx: *mut c_void,
    mdname: *const c_char,
    vprovkey: *mut c_void,
    _params: *const OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    const SUCCESS_RET: c_int = 1;
    trace!(target: log_target!(), "{}", "Called!");

    let sigctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());

    // From https://github.com/openssl/openssl/blob/95051052b319d346a8aa3d34d6105d683bb77294/providers/implementations/signature/ml_dsa_sig.c#L157-L175

    if !mdname.is_null() && unsafe { *mdname.offset(0) } != (0 as c_char) {
        error!(target: log_target!(), "Explicit digest not supported for ML-DSA operations");
        return ERROR_RET;
    }

    let provkey: &mut KeyPair = handleResult!(vprovkey.try_into());

    let _ = handleResult!(sigctx.verify_init(provkey));

    return SUCCESS_RET;
}

#[named]
pub(super) unsafe extern "C" fn digest_verify(
    vsigctx: *mut c_void,
    sig: *const c_uchar,
    siglen: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    const ERROR_RET: c_int = -1;
    const FALSE_RET: c_int = 0;
    const TRUE_RET: c_int = 1;

    trace!(target: log_target!(), "Called!");

    let sigctx: &mut SignatureContext<'_> = handleResult!(vsigctx.try_into());

    if sig.is_null() {
        error!(target: log_target!(), "sig was NULL");
        return ERROR_RET;
    }
    assert_eq!(siglen, super::SIGNATURE_LEN);
    let sig_slice = handleResult!(u8_slice_try_from_raw_parts(sig, siglen));
    let sig = handleResult!(Signature::try_from(sig_slice));

    if tbs.is_null() {
        error!(target: log_target!(), "tbs was NULL");
        return ERROR_RET;
    }
    let msg = unsafe { std::slice::from_raw_parts(tbs, tbslen) };

    let ret = sigctx.verify(msg, &sig);

    match ret {
        Ok(_) => {
            trace!(target: log_target!(), "Signature verification succeeded");
            return TRUE_RET;
        }
        Err(e) => {
            let e = VerificationError::from(e);
            match e {
                VerificationError::InvalidSignature => {
                    debug!(target: log_target!(), "Signature verification failed!");
                    return FALSE_RET;
                }
                e => {
                    error!(target: log_target!(), "{e:?}");
                    return ERROR_RET;
                }
            }
        }
    }
}

#[named]
pub(super) unsafe extern "C" fn digest_sign_init(
    vsigctx: *mut c_void,
    mdname: *const c_char,
    vprovkey: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    if !mdname.is_null() && unsafe { *mdname.offset(0) } != (0 as c_char) {
        error!(target: log_target!(), "Explicit digest not supported for ML-DSA operations");
        return ERROR_RET;
    }

    sign_init(vsigctx, vprovkey, params)
}

#[named]
pub(super) unsafe extern "C" fn digest_sign(
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

    sign(vsigctx, sig, siglen, sigsize, tbs, tbslen)
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
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signature = sigctx.try_sign(&msg).unwrap();
        assert_eq!(signature.encoded_len(), SIGNATURE_LEN);
        // (this test succeeds if we've gotten this far without anything exploding)
    }

    #[test]
    fn test_sign_and_verify_success() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signature = sigctx.try_sign(&msg).unwrap();
        assert_eq!(signature.encoded_len(), SIGNATURE_LEN);
        let sig_bytes = signature.to_bytes();
        let sig_bytes = sig_bytes.as_ref();
        let sig = Signature::try_from(sig_bytes).unwrap();
        // verify the signature
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&msg, &sig).is_ok());
    }

    #[test]
    fn test_sign_and_verify_wrong_key_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signature = sigctx.try_sign(&msg).unwrap();
        let sig = signature.to_bytes();
        let sig = sig.as_ref();
        let sig = Signature::try_from(sig).unwrap();
        // generate another keypair
        let other_keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        // confirm that verification with the new key fails
        sigctx.verify_init(&other_keypair).unwrap();
        let ret = sigctx.verify(&msg, &sig);
        assert!(ret.is_err());
    }

    #[test]
    fn test_sign_and_verify_tampered_sig_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signature = sigctx.try_sign(&msg).unwrap().to_bytes();
        let signature = signature.as_ref();
        let mut mut_sig = [0; SIGNATURE_LEN];
        mut_sig.copy_from_slice(signature);
        // flip a bit in the signature
        mut_sig[2] = std::ops::BitXor::bitxor(mut_sig[2], 1u8);
        let sig = Signature::try_from(mut_sig.as_slice()).unwrap();
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&msg, &sig).is_err());
    }

    #[test]
    fn test_sign_and_verify_tampered_msg_failure() {
        let testctx = setup().expect("Failed to initialize test setup");
        let provctx = testctx.provctx;

        // generate keypair
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        let mut sigctx = SignatureContext::new(&provctx);
        // sign a message with it
        let msg: [u8; 5] = [1, 2, 3, 4, 5];
        sigctx.sign_init(&keypair).unwrap();
        let signature = sigctx.try_sign(&msg).unwrap().to_bytes();
        let signature = signature.as_ref();
        let sig = Signature::try_from(signature).unwrap();
        // construct a different message of the same length
        let other_msg: [u8; 5] = [1, 2, 3, 8, 5];
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&other_msg, &sig).is_err());
        // construct a longer message with the same initial contents
        let other_msg: [u8; 6] = [1, 2, 3, 4, 5, 6];
        // confirm that verification fails
        sigctx.verify_init(&keypair).unwrap();
        assert!(sigctx.verify(&other_msg, &sig).is_err());
    }
}

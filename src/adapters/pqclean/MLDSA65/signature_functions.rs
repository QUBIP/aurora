use super::keymgmt_functions::KeyPair;
use super::OurError as SignatureError;
use super::*;
use crate::named;
use libc::{c_uchar, c_void};

#[expect(dead_code)]
struct SignatureContext<'a> {
    keypair: Option<&'a KeyPair<'a>>,
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

#[named]
pub(super) extern "C" fn newctx(vprovctx: *mut c_void, _propq: *const c_uchar) -> *mut c_void {
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
    let sig_ctx = Box::new(SignatureContext {
        keypair: None,
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
    use crate::tests::new_provctx_for_testing;

    #[test]
    #[cfg(any())]
    fn test_sign_and_verify_success() {
        // generate keypair
        // sign a message with it
        // verify the signature
    }

    #[test]
    #[should_panic]
    #[cfg(any())]
    fn test_sign_and_verify_wrong_key_failure() {
        // generate keypair
        // sign a message with it
        // generate another keypair
        // confirm that verification with the new key fails
    }

    #[test]
    #[should_panic]
    #[cfg(any())]
    fn test_sign_and_verify_tampered_sig_failure() {
        // generate keypair
        // sign a message with it
        // flip a bit in the signature
        // confirm that verification fails
    }
}

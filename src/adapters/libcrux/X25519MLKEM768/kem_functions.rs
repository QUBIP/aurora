use super::*;
use bindings::ossl_param_st;
use libc::{c_int, c_uchar, c_void};

use crate::adapters::libcrux::X25519MLKEM768::keymgmt_functions::KeyPair;



#[expect(dead_code)]
struct KemContext<'a>{
    private_key: Option<&'a libcrux_kem::PrivateKey>,
    public_key: Option<&'a libcrux_kem::PublicKey>,
    provctx: *mut c_void, 
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
pub(super) extern "C" fn freectx(vkemctx: *mut c_void) /* -> c_void */ {
    trace!(target: log_target!(), "{}", "Called!");
    if !vkemctx.is_null() {
        let kem_ctx: Box<KemContext> = unsafe { Box::from_raw(vkemctx.cast()) };
        drop(kem_ctx);
    }
    //todo!("Reclaim and drop vkemctx")
}

#[named]
pub(super) extern "C" fn encapsulate_init(
    vkemctx: *mut c_void,
    provkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    if vkemctx.is_null() || provkey.is_null() {
        return 0;
    }

    let kem_ctx: &mut KemContext = unsafe { &mut *(vkemctx as *mut KemContext) };

    let keypair: &mut KeyPair = unsafe { &mut *(provkey as *mut KeyPair) };

    kem_ctx.private_key = keypair.private.as_ref();
    kem_ctx.public_key = keypair.public.as_ref();


    1 
    //todo!("Init encapsulate operation ctx")
}

#[named]
pub(super) extern "C" fn decapsulate_init(
    _vkemctx: *mut c_void,
    _provkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    todo!("Init decapsulate operation ctx")
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

       
        let kem_ctx: &mut KemContext = unsafe { &mut *(ctx as *mut KemContext) };

        let public_key = kem_ctx
            .public_key
            .as_ref()
            .expect("Public key is missing from the context");

        let mut rng = rand::rngs::OsRng;
        let (shared_secret, ciphertext) = public_key
            .encapsulate(&mut rng)
            .expect("Encapsulation failed");

        unsafe {
            std::ptr::copy_nonoverlapping(ciphertext.encode().as_ptr(), out, ciphertext.encode().len());
            *outlen = ciphertext.encode().len();

            std::ptr::copy_nonoverlapping(shared_secret.encode().as_ptr(), secret, shared_secret.encode().len());
            *secretlen = shared_secret.encode().len();
        }

        1 

        //todo!("Perform encapsulate")
    }

#[named]
pub(super) extern "C" fn decapsulate(
    _ctx: *mut c_void,
    _out: *mut c_uchar,
    _outlen: *mut usize,
    _in_: *const c_uchar,
    _inlen: usize,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    todo!("Perform decapsulate")
}

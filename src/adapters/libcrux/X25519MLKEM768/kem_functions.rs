use super::*;
use bindings::ossl_param_st;
use libc::{c_int, c_uchar, c_void};

#[named]
pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &mut OpenSSLProvider<'_> = vprovctx.into();

    todo!("Create a new KEM ctx")
}

#[named]
pub(super) extern "C" fn freectx(_vkemctx: *mut c_void) -> c_void {
    trace!(target: log_target!(), "{}", "Called!");

    todo!("Reclaim and drop vkemctx")
}

#[named]
pub(super) extern "C" fn encapsulate_init(
    _vkemctx: *mut c_void,
    _provkey: *mut c_void,
    _params: *mut ossl_param_st,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    todo!("Init encapsulate operation ctx")
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
    _ctx: *mut c_void,
    _out: *mut c_uchar,
    _outlen: *mut usize,
    _secret: *mut c_uchar,
    _secretlen: *mut usize,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    todo!("Perform encapsulate")
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

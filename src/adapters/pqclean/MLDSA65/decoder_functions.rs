use super::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use forge::osslparams::*;
use libc::{c_int, c_void};

struct DecoderContext {}

// TODO fill this in with the values we support (of the OSSL_KEYMGMT_SELECT_* constants)
const SELECTION_MASK: c_int = 0;

#[named]
pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    let decoder_ctx = Box::new(DecoderContext {});

    Box::into_raw(decoder_ctx).cast()
}

#[named]
pub(super) extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = params;
    warn!("Ignoring params");

    todo!();
}

#[named]
pub(super) extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    todo!();
}

#[named]
pub(super) extern "C" fn freectx(vdecoderctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");

    if !vdecoderctx.is_null() {
        let decoder_ctx: Box<DecoderContext> = unsafe { Box::from_raw(vdecoderctx.cast()) };
        drop(decoder_ctx);
    }
}

#[named]
pub(super) extern "C" fn set_ctx_params(
    vdecoderctx: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = vdecoderctx;
    let _ = params;
    warn!("Ignoring vdecoderctx and params");

    todo!();
}

#[named]
pub(super) extern "C" fn settable_ctx_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    static LIST: &[CONST_OSSL_PARAM] = &[
        OSSLParam::new_const_utf8string(OSSL_DECODER_PARAM_PROPERTIES, None),
        CONST_OSSL_PARAM::END,
    ];

    let first: &bindings::OSSL_PARAM = &LIST[0];
    let ptr: *const bindings::OSSL_PARAM = std::ptr::from_ref(first);

    return ptr;
}

// based on oqsprov/oqs_decode_der2key.c:der2key_check_selection() in the OQS provider
#[named]
pub(super) extern "C" fn does_selection(vprovctx: *mut c_void, selection: c_int) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    debug!(target: log_target!(), "selection: {:?}", selection);

    if selection == 0 {
        return 1;
    }

    let checks = [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    ];
    for check in checks {
        let check = check as c_int;
        // FIXME use the bitmask crate to do these comparisons
        if selection & check != 0 {
            return (SELECTION_MASK & check != 0) as c_int;
        }
    }

    return 0;
}

#[named]
pub(super) extern "C" fn decode(
    vdecoderctx: *mut c_void,
    in_: *mut OSSL_CORE_BIO,
    selection: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = vdecoderctx;
    let _ = in_;
    let _ = selection;
    let _ = data_cb;
    let _ = data_cbarg;
    let _ = pw_cb;
    let _ = pw_cbarg;
    warn!("Ignoring all arguments");

    todo!();
}

#[named]
pub(super) extern "C" fn export_object(
    vdecoderctx: *mut c_void,
    objref: *const c_void,
    objref_sz: usize,
    export_cb: OSSL_CALLBACK,
    export_cbarg: *mut c_void,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = vdecoderctx;
    let _ = objref;
    let _ = objref_sz;
    let _ = export_cb;
    let _ = export_cbarg;
    warn!("Ignoring all arguments");

    todo!();
}

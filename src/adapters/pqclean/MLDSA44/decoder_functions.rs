use super::*;
use asn1::{ParseError, ParseErrorKind};
use bindings::ffi_c_types::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use forge::operations::{keymgmt, transcoders};
use forge::ossl_callback::OSSLCallback;
use forge::osslparams::*;
use keymgmt::selection::Selection;
use pkcs8::der::Decode;
use transcoders::{Decoder, DoesSelection};

use pkcs8;

use keymgmt_functions::asn_definitions::PrivateKey as ASNPrivateKey;

struct DecoderContext<'a> {
    provctx: &'a ProviderInstance<'a>,
}

impl<'a> DecoderContext<'a> {
    pub(super) fn new(provctx: &'a ProviderInstance<'a>) -> Self {
        Self { provctx }
    }
}

impl<'a> TryFrom<*mut c_void> for &mut DecoderContext<'a> {
    type Error = OurError;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl TryFrom<*mut c_void> for &mut DecoderContext"
        );
        let ptr = vptr as *mut DecoderContext;
        if ptr.is_null() {
            return Err(anyhow::anyhow!("vptr was null"));
        }
        Ok(unsafe { &mut *ptr })
    }
}

impl<'a> TryFrom<*mut c_void> for &DecoderContext<'a> {
    type Error = OurError;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl TryFrom<*mut c_void> for &mut DecoderContext"
        );
        let ptr = vptr as *mut DecoderContext;
        if ptr.is_null() {
            return Err(anyhow::anyhow!("vptr was null"));
        }
        Ok(unsafe { &mut *ptr })
    }
}

#[named]
pub(super) unsafe extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
    const ERROR_RET: *mut c_void = std::ptr::null_mut();
    trace!(target: log_target!(), "{}", "Called!");
    let provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());

    let decoder_ctx = Box::new(DecoderContext::new(provctx));

    Box::into_raw(decoder_ctx).cast()
}

#[named]
pub(super) unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = params;
    warn!(target: log_target!(), "Ignoring params");

    todo!();
}

#[named]
pub(super) unsafe extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());

    std::ptr::from_ref(&CONST_OSSL_PARAM::END)
}

#[named]
pub(super) unsafe extern "C" fn freectx(vdecoderctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");

    if !vdecoderctx.is_null() {
        let decoder_ctx: Box<DecoderContext> = unsafe { Box::from_raw(vdecoderctx.cast()) };
        drop(decoder_ctx);
    }
}

/// Decodes a SubjectPublicKeyInfo DER blob
///
/// # Arguments
///
/// ## TODO(🛠️): document arguments
///
/// # Notes
///
/// [`OSSL_FUNC_decoder_decode_fn`][provider-decoder(7ossl)]
/// functions such as this one are tightly integrated
/// with the [`super::keymgmt_functions::load`]
/// implementation exposed
/// for [their algorithm][`super`].
///
/// Eventually the `data_cb` argument calls the
/// `OSSL_FUNC_keymgmt_load_fn`
/// exposed by the [keymgmt][`super::keymgmt_functions`]
/// for [this algorithm][`super`].
/// Hence they must agree on how the reference is being passed around.
///
/// Refer to [provider-decoder(7ossl)],
/// [provider-keymgmt(7ossl)],
/// and [provider-object(7ossl)].
///
/// [provider-keymgmt(7ossl)]: https://docs.openssl.org/master/man7/provider-keymgmt/
/// [provider-object(7ossl)]: https://docs.openssl.org/master/man7/provider-object/
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
///
/// # Examples
///
/// ## TODO(🛠️): add examples
///
// based on oqsprov/oqs_decode_der2key.c:oqs_der2key_decode() in the OQS provider
#[named]
pub(super) unsafe extern "C" fn decodeSPKI(
    vdecoderctx: *mut c_void,
    in_: *mut OSSL_CORE_BIO,
    selection: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    _pw_cb: OSSL_PASSPHRASE_CALLBACK,
    _pw_cbarg: *mut c_void,
) -> c_int {
    // See https://docs.openssl.org/3.2/man7/provider-decoder/#decoding-functions for an explanation of the meaning of these return values
    const CONTINUE_DECODING_PROCESS: c_int = 1;
    const STOP_DECODING_PROCESS: c_int = 0;
    const ERROR_RET: c_int = STOP_DECODING_PROCESS;

    trace!(target: log_target!(), "{}", "Called!");

    trace!(target: log_target!(), "Got selection in decode(): {:#b}", selection);
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return STOP_DECODING_PROCESS;
    }

    let decoderctx: &DecoderContext = handleResult!(vdecoderctx.try_into());
    let cb = handleResult!(OSSLCallback::try_new(data_cb, data_cbarg));

    let bytes = handleResult!(decoderctx.provctx.BIO_read_ex(in_));
    trace!(target: log_target!(), "Read {} bytes in decode()", bytes.len());

    // I don't think these are used, since set_ctx_params is never called to set them....
    // https://docs.openssl.org/3.2/man7/property/#global-and-local
    // debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

    let spki = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(bytes.as_ref());

    let spki = match spki {
        Ok(spki) => spki,
        Err(e) => {
            debug!(target: log_target!(), "Bailing out: Failed to decode SubjectPublicKeyInfo: {e:?}");
            return CONTINUE_DECODING_PROCESS;
        }
    };
    let oid = spki.algorithm.oid;
    if oid != super::OID_PKCS8 {
        debug!(target: log_target!(), "Bailing out: OID mismatch: found {oid:}, expected {}", super::OID_PKCS8);
        return CONTINUE_DECODING_PROCESS;
    }

    // After this point errors are logged as such, as supposedly this decoder should be authoritative for this algorithm

    if spki.algorithm.parameters.is_some() {
        error!(target: log_target!(), "Algorithm parameters are not allowed for this decoder");
        return STOP_DECODING_PROCESS;
    }

    let derpubkey = match spki.subject_public_key.as_bytes() {
        Some(b) => b,
        None => {
            error!(target: log_target!(), "Nested bit-string is not octet aligned, hence it is not DER-encoded");
            return STOP_DECODING_PROCESS;
        }
    };
    let pk = match keymgmt_functions::PublicKey::from_DER(derpubkey) {
        Ok(pk) => pk,
        Err(e) => {
            error!(target: log_target!(), "Failed to decode public key: {e:?}");
            return STOP_DECODING_PROCESS;
        }
    };
    let kp: Box<keymgmt_functions::KeyPair<'_>> = Box::new(
        super::keymgmt_functions::KeyPair::from_parts(decoderctx.provctx, None, Some(pk)),
    );
    let len = std::mem::size_of::<keymgmt_functions::KeyPair>();
    let kp_ptr = Box::into_raw(kp);
    // convert to c_char to match the type signature of OSSLParam::new_const_octetstring
    let ref_slice: &[c_char] = unsafe { std::slice::from_raw_parts(kp_ptr as *const c_char, len) };

    // TODO this constant comes from core_object.h in openssl: include that file in the wrapper.h
    // file we feed to bindgen in the forge, so a binding gets generated for it
    const OSSL_OBJECT_PKEY: c_int = 2;

    // Pass it by reference, as per https://docs.openssl.org/master/man7/provider-object/
    let params = &[
        OSSLParam::new_const_int(OSSL_OBJECT_PARAM_TYPE, Some(&OSSL_OBJECT_PKEY)),
        OSSLParam::new_const_utf8string(OSSL_OBJECT_PARAM_DATA_TYPE, Some(&super::NAME)),
        OSSLParam::new_const_octetstring(OSSL_OBJECT_PARAM_REFERENCE, Some(&ref_slice)),
        CONST_OSSL_PARAM::END,
    ];

    trace!(target: log_target!(), "Ignoring pw_cb and pw_cbarg");
    let ret = cb.call(params.as_ptr() as *const OSSL_PARAM);

    return ret;
}

/// WIP! Decodes a PrivateKeyInfo DER blob
///
/// # Arguments
///
/// ## TODO(🛠️): document arguments
///
/// # Notes
///
/// [`OSSL_FUNC_decoder_decode_fn`][provider-decoder(7ossl)]
/// functions such as this one are tightly integrated
/// with the [`super::keymgmt_functions::load`]
/// implementation exposed
/// for [their algorithm][`super`].
///
/// Eventually the `data_cb` argument calls the
/// `OSSL_FUNC_keymgmt_load_fn`
/// exposed by the [keymgmt][`super::keymgmt_functions`]
/// for [this algorithm][`super`].
/// Hence they must agree on how the reference is being passed around.
///
/// Refer to [provider-decoder(7ossl)],
/// [provider-keymgmt(7ossl)],
/// and [provider-object(7ossl)].
///
/// [provider-keymgmt(7ossl)]: https://docs.openssl.org/master/man7/provider-keymgmt/
/// [provider-object(7ossl)]: https://docs.openssl.org/master/man7/provider-object/
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
///
/// # Examples
///
/// ## TODO(🛠️): add examples
///
// based on oqsprov/oqs_decode_der2key.c:oqs_der2key_decode() in the OQS provider
#[named]
pub(super) unsafe extern "C" fn decodePrivateKeyInfo(
    vdecoderctx: *mut c_void,
    in_: *mut OSSL_CORE_BIO,
    selection: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    _pw_cb: OSSL_PASSPHRASE_CALLBACK,
    _pw_cbarg: *mut c_void,
) -> c_int {
    // See https://docs.openssl.org/3.2/man7/provider-decoder/#decoding-functions for an explanation of the meaning of these return values
    const CONTINUE_DECODING_PROCESS: c_int = 1;
    const STOP_DECODING_PROCESS: c_int = 0;
    const ERROR_RET: c_int = STOP_DECODING_PROCESS;

    trace!(target: log_target!(), "{}", "Called!");

    trace!(target: log_target!(), "Got selection in decode(): {:#b}", selection);
    // TODO is this the right check to be making?
    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return STOP_DECODING_PROCESS;
    }

    let decoderctx: &DecoderContext = handleResult!(vdecoderctx.try_into());
    let cb = handleResult!(OSSLCallback::try_new(data_cb, data_cbarg));

    let bytes = handleResult!(decoderctx.provctx.BIO_read_ex(in_));
    trace!(target: log_target!(), "Read {} bytes in decode()", bytes.len());

    // I don't think these are used, since set_ctx_params is never called to set them....
    // https://docs.openssl.org/3.2/man7/property/#global-and-local
    // debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

    let pki = pkcs8::PrivateKeyInfo::try_from(bytes.as_ref());

    let pki = match pki {
        Ok(pki) => pki,
        Err(e) => {
            error!(target: log_target!(), "Failed to decode PrivateKeyInfo: {e:?}");
            return STOP_DECODING_PROCESS;
        }
    };
    if pki.version() != pkcs8::Version::V1 {
        debug!(target: log_target!(), "Bailing out: This decoder only supports RFC5208 (PKCS8 V1)");
        return CONTINUE_DECODING_PROCESS;
    }

    let oid = pki.algorithm.oid;
    if oid != super::OID_PKCS8 {
        debug!(target: log_target!(), "Bailing out: OID mismatch: found {oid:}, expected {}", super::OID_PKCS8);
        return CONTINUE_DECODING_PROCESS;
    }

    // After this point errors are logged as such, as supposedly this decoder should be authoritative for this algorithm

    if pki.algorithm.parameters.is_some() {
        error!(target: log_target!(), "Algorithm parameters are not allowed for this decoder");
        return STOP_DECODING_PROCESS;
    }

    let derprivkey = pki.private_key;
    let pair = match keymgmt_functions::PrivateKey::from_DER(derprivkey) {
        Ok(pair) => pair,
        Err(e) => {
            error!(target: log_target!(), "Failed to decode private key: {e:?}");
            return STOP_DECODING_PROCESS;
        }
    };
    let (privkey, pubkey) = match pair {
        (sk, None) => {
            let pk = match sk.derive_public_key() {
                Some(pk) => pk,
                None => {
                    error!(target: log_target!(), "Failed to derive public key from secret key");
                    return STOP_DECODING_PROCESS;
                }
            };
            (sk, pk)
        }
        (sk, Some(pk)) => (sk, pk),
    };

    let kp: Box<keymgmt_functions::KeyPair<'_>> =
        Box::new(super::keymgmt_functions::KeyPair::from_parts(
            decoderctx.provctx,
            Some(privkey),
            Some(pubkey),
        ));
    let len = std::mem::size_of::<keymgmt_functions::KeyPair>();
    let kp_ptr = Box::into_raw(kp);
    // convert to c_char to match the type signature of OSSLParam::new_const_octetstring
    let ref_slice: &[c_char] = unsafe { std::slice::from_raw_parts(kp_ptr as *const c_char, len) };

    // TODO this constant comes from core_object.h in openssl: include that file in the wrapper.h
    // file we feed to bindgen in the forge, so a binding gets generated for it
    const OSSL_OBJECT_PKEY: c_int = 2;

    // Pass it by reference, as per https://docs.openssl.org/master/man7/provider-object/
    let params = &[
        OSSLParam::new_const_int(OSSL_OBJECT_PARAM_TYPE, Some(&OSSL_OBJECT_PKEY)),
        OSSLParam::new_const_utf8string(OSSL_OBJECT_PARAM_DATA_TYPE, Some(&super::NAME)),
        OSSLParam::new_const_octetstring(OSSL_OBJECT_PARAM_REFERENCE, Some(&ref_slice)),
        CONST_OSSL_PARAM::END,
    ];

    trace!(target: log_target!(), "Ignoring pw_cb and pw_cbarg");
    let ret = cb.call(params.as_ptr() as *const OSSL_PARAM);

    trace!(target: log_target!(), "Returning {ret:?}");
    return ret;
}

/// A _DER_ [Decoder][provider-decoder(7ossl)] for _SubjectPublicKeyInfo_
///
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
pub(crate) struct DER2SubjectPublicKeyInfo();

impl Decoder for DER2SubjectPublicKeyInfo {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='SubjectPublicKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_decoder_decode_fn, OSSL_FUNC_DECODER_DECODE};
            use bindings::{OSSL_FUNC_decoder_does_selection_fn, OSSL_FUNC_DECODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_decoder_freectx_fn, OSSL_FUNC_DECODER_FREECTX};
            use bindings::{OSSL_FUNC_decoder_newctx_fn, OSSL_FUNC_DECODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_DECODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_NEWCTX,
                    OSSL_FUNC_decoder_newctx_fn,
                    decoder_functions::newctx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_FREECTX,
                    OSSL_FUNC_decoder_freectx_fn,
                    decoder_functions::freectx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_DOES_SELECTION,
                    OSSL_FUNC_decoder_does_selection_fn,
                    decoder_functions::does_selection_SPKI
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_DECODE,
                    OSSL_FUNC_decoder_decode_fn,
                    decoder_functions::decodeSPKI
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::DER_DECODER_FUNCTIONS
    };
}

impl DoesSelection for DER2SubjectPublicKeyInfo {
    const SELECTION_MASK: Selection = Selection::PUBLIC_KEY;
}

transcoders::make_does_selection_fn!(
    does_selection_SPKI,
    DER2SubjectPublicKeyInfo,
    ProviderInstance
);

/// A _DER_ [Decoder][provider-decoder(7ossl)] for _PrivateKeyInfo_
///
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
pub(crate) struct DER2PrivateKeyInfo();

impl Decoder for DER2PrivateKeyInfo {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='PrivateKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_decoder_decode_fn, OSSL_FUNC_DECODER_DECODE};
            use bindings::{OSSL_FUNC_decoder_does_selection_fn, OSSL_FUNC_DECODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_decoder_freectx_fn, OSSL_FUNC_DECODER_FREECTX};
            use bindings::{OSSL_FUNC_decoder_newctx_fn, OSSL_FUNC_DECODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_DECODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_NEWCTX,
                    OSSL_FUNC_decoder_newctx_fn,
                    decoder_functions::newctx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_FREECTX,
                    OSSL_FUNC_decoder_freectx_fn,
                    decoder_functions::freectx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_DOES_SELECTION,
                    OSSL_FUNC_decoder_does_selection_fn,
                    decoder_functions::does_selection_PrivateKeyInfo
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_DECODE,
                    OSSL_FUNC_decoder_decode_fn,
                    decoder_functions::decodePrivateKeyInfo
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::DER_DECODER_FUNCTIONS
    };
}

impl DoesSelection for DER2PrivateKeyInfo {
    const SELECTION_MASK: Selection = Selection::KEYPAIR;
}
transcoders::make_does_selection_fn!(
    does_selection_PrivateKeyInfo,
    DER2PrivateKeyInfo,
    ProviderInstance
);

use super::*;
use bindings::ffi_c_types::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use decoder::{Decoder, DoesSelection};
use forge::operations::{decoder, keymgmt};
use forge::ossl_callback::OSSLCallback;
use forge::osslparams::*;
use keymgmt::selection::Selection;

struct DecoderContext<'a> {
    provctx: &'a OpenSSLProvider<'a>,
}

impl<'a> DecoderContext<'a> {
    pub(super) fn new(provctx: &'a OpenSSLProvider<'a>) -> Self {
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
    let provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

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
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

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
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection in decode(): {:#b}", selection);
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return ERROR_RET;
    }

    let decoderctx: &DecoderContext = handleResult!(vdecoderctx.try_into());
    let cb = handleResult!(OSSLCallback::try_new(data_cb, data_cbarg));

    let bytes = handleResult!(decoderctx.provctx.BIO_read_ex(in_));
    debug!(target: log_target!(), "Read {} bytes in decode()", bytes.len());

    // I don't think these are used, since set_ctx_params is never called to set them....
    // https://docs.openssl.org/3.2/man7/property/#global-and-local
    // debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

    let result: asn1::ParseResult<_> = asn1::parse(&bytes, |d| {
        return d.read_element::<asn1::Sequence>()?.parse(|d| {
            let algorithm_identifier = d.read_element::<asn1::Sequence>()?.parse(|d| {
                let algorithm_identifier = d.read_element::<asn1::ObjectIdentifier>()?;
                return Ok(algorithm_identifier);
            })?;
            let subject_public_key = d.read_element::<asn1::BitString>()?;
            return Ok((algorithm_identifier, subject_public_key));
        });
    });

    // wrapping the asn1::parse() call itself in handleResult!() leaves the compiler too little
    // information to be able to infer types, so I left it like this for now
    let (oid, key) = handleResult!(result);

    // yes, this really is the "right" way to do this (see the asn1::ObjectIdentifier docs)
    if oid != asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 18) {
        panic!("OID mismatch: found {}", oid);
    }

    let key_bytes = key.as_bytes();
    let pk = handleResult!(keymgmt_functions::PublicKey::decode(key_bytes));
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
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection in decode(): {:#b}", selection);
    // TODO is this the right check to be making?
    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return ERROR_RET;
    }

    let decoderctx: &DecoderContext = handleResult!(vdecoderctx.try_into());
    let cb = handleResult!(OSSLCallback::try_new(data_cb, data_cbarg));

    let bytes = handleResult!(decoderctx.provctx.BIO_read_ex(in_));
    debug!(target: log_target!(), "Read {} bytes in decode()", bytes.len());

    // I don't think these are used, since set_ctx_params is never called to set them....
    // https://docs.openssl.org/3.2/man7/property/#global-and-local
    // debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

    let result: asn1::ParseResult<_> = asn1::parse(&bytes, |d| {
        return d.read_element::<asn1::Sequence>()?.parse(|d| {
            let _version = d.read_element::<asn1::BigInt>()?;
            let algorithm_identifier = d.read_element::<asn1::Sequence>()?.parse(|d| {
                let algorithm_identifier = d.read_element::<asn1::ObjectIdentifier>()?;
                return Ok(algorithm_identifier);
            })?;
            let keydata = d.read_element::<asn1::OctetStringEncoded<&[u8]>>()?;
            return Ok((algorithm_identifier, keydata));
        });
    });

    debug!(target: log_target!(), "Parsed private key material out of ASN.1 for decoding!");

    // wrapping the asn1::parse() call itself in handleResult!() leaves the compiler too little
    // information to be able to infer types, so I left it like this for now
    let (oid, keydata) = handleResult!(result);

    // yes, this really is the "right" way to do this (see the asn1::ObjectIdentifier docs)
    if oid != asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 18) {
        panic!("OID mismatch: found {}", oid);
    }

    // the raw bytes in the octet string include a prefix indicating their type and length,
    // which gets interpreted here in the .get() call
    // see section 5.10 (DER encoding): https://luca.ntop.org/Teaching/Appunti/asn1.html
    let key_bytes = keydata.get();

    // I don't know where it's specified that the private key comes first, but it seems to be true,
    // based on inspecting a private+public key file we've been using for testing.
    let cutoff = pqcrypto_mldsa::mldsa65::secret_key_bytes();
    let privkey = handleResult!(keymgmt_functions::PrivateKey::decode(&key_bytes[0..cutoff]));
    let pubkey = handleResult!(keymgmt_functions::PublicKey::decode(&key_bytes[cutoff..]));
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
        mod dispath_table_module {
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

        dispath_table_module::DER_DECODER_FUNCTIONS
    };
}

impl DoesSelection for DER2SubjectPublicKeyInfo {
    const SELECTION_MASK: Selection = Selection::PUBLIC_KEY;
}

decoder::make_does_selection_fn!(does_selection_SPKI, DER2SubjectPublicKeyInfo);

/// A _DER_ [Decoder][provider-decoder(7ossl)] for _PrivateKeyInfo_
///
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
pub(crate) struct DER2PrivateKeyInfo();

impl Decoder for DER2PrivateKeyInfo {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='PrivateKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispath_table_module {
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

        dispath_table_module::DER_DECODER_FUNCTIONS
    };
}

impl DoesSelection for DER2PrivateKeyInfo {
    const SELECTION_MASK: Selection = Selection::KEYPAIR;
}
decoder::make_does_selection_fn!(does_selection_PrivateKeyInfo, DER2PrivateKeyInfo);

use super::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use forge::ossl_callback::OSSLCallback;
use forge::osslparams::*;
use libc::{c_char, c_int, c_void};
use std::ffi::CString;

struct DecoderContext<'a> {
    provctx: &'a OpenSSLProvider<'a>,
    // worry about ownership later
    properties: Option<CString>,
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

    let decoder_ctx = Box::new(DecoderContext {
        provctx,
        properties: None,
    });

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

#[named]
pub(super) unsafe extern "C" fn set_ctx_params(
    vdecoderctx: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");
    const ERROR_RET: c_int = 0;
    const SUCCESS: c_int = 1;

    let decoderctx: &mut DecoderContext = handleResult!(vdecoderctx.try_into());

    let params = match OSSLParam::try_from(params) {
        Ok(params) => params,
        Err(e) => {
            error!(target: log_target!(), "Failed decoding params: {:?}", e);
            return ERROR_RET;
        }
    };

    for p in params {
        let key = match p.get_key() {
            Some(key) => key,
            None => {
                error!(target: log_target!(), "Param without valid key {:?}", p);
                return ERROR_RET;
            }
        };

        if key == OSSL_DECODER_PARAM_PROPERTIES {
            let bytes: &[u8] = match p.get() {
                Some(bytes) => bytes,
                None => handleResult!(Err(anyhow!("Invalid OSSL_DECODER_PARAM_PROPERTIES"))),
            };
            debug!(target: log_target!(), "The received properties are: {:X?}", bytes);
            debug!(target: log_target!(), "And as a string: {:X?}", CString::new(bytes));

            decoderctx.properties =
                Some(CString::new(bytes).expect("properties should be parseable as CString"));
        } else {
            debug!(target: log_target!(), "Ignoring param {:?}", key);
        }
    }
    return SUCCESS;
}

#[named]
pub(super) unsafe extern "C" fn settable_ctx_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
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
macro_rules! make_does_selection_fn {
    ( $fn_name:ident, $selection_mask:expr ) => {
        #[named]
        pub(super) unsafe extern "C" fn $fn_name(vprovctx: *mut c_void, selection: c_int) -> c_int {
            const ERROR_RET: c_int = 0;
            trace!(target: log_target!(), "{}", "Called!");
            let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

            let selection = selection as u32;
            debug!(target: log_target!(), "selection: {:#b}", selection);
            debug!(target: log_target!(), "we're offering: {:#b}", $selection_mask);

            if selection == 0 {
                return 1;
            }

            let checks = [
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
            ];
            for check in checks {
                // FIXME use the bitmask crate to do these comparisons
                if selection & check != 0 {
                    return ($selection_mask & check != 0) as c_int;
                }
            }

            return 0;
        }
    }
}

make_does_selection_fn!(does_selection_SPKI, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
make_does_selection_fn!(does_selection_PrivateKeyInfo, OSSL_KEYMGMT_SELECT_KEYPAIR);

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
    debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

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
    debug!(target: log_target!(), "Using properties: {:?}", decoderctx.properties);

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

#[named]
pub(super) unsafe extern "C" fn export_object(
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
    warn!(target: log_target!(), "Ignoring all arguments");

    todo!();
}

// FIXME: this should likely be in openssl_provider_forge, and maybe defined as a trait
pub(crate) struct DECODER {
    pub(crate) property_definition: &'static CStr,
    pub(crate) selection_mask: c_int,
    pub(crate) dispatch_table: &'static [OSSL_DISPATCH],
}

/// A _DER_ [Decoder][provider-decoder(7ossl)] for _SubjectPublicKeyInfo_
///
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
#[expect(non_upper_case_globals)]
pub(crate) const DER2SubjectPublicKeyInfo_DECODER: DECODER = DECODER {
    property_definition:
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='SubjectPublicKeyInfo'",
    selection_mask: OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int,
    dispatch_table: {
        mod dispath_table_module {
            #![expect(unused_imports)] // FIXME: get rid of this

            use super::*;
            use bindings::{OSSL_FUNC_decoder_decode_fn, OSSL_FUNC_DECODER_DECODE};
            use bindings::{OSSL_FUNC_decoder_does_selection_fn, OSSL_FUNC_DECODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_decoder_export_object_fn, OSSL_FUNC_DECODER_EXPORT_OBJECT};
            use bindings::{OSSL_FUNC_decoder_freectx_fn, OSSL_FUNC_DECODER_FREECTX};
            use bindings::{OSSL_FUNC_decoder_get_params_fn, OSSL_FUNC_DECODER_GET_PARAMS};
            use bindings::{
                OSSL_FUNC_decoder_gettable_params_fn, OSSL_FUNC_DECODER_GETTABLE_PARAMS,
            };
            use bindings::{OSSL_FUNC_decoder_newctx_fn, OSSL_FUNC_DECODER_NEWCTX};
            use bindings::{OSSL_FUNC_decoder_set_ctx_params_fn, OSSL_FUNC_DECODER_SET_CTX_PARAMS};
            use bindings::{
                OSSL_FUNC_decoder_settable_ctx_params_fn, OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
            };

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_DECODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_GET_PARAMS,
                    OSSL_FUNC_decoder_get_params_fn,
                    decoder_functions::get_params
                ),
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_GETTABLE_PARAMS,
                    OSSL_FUNC_decoder_gettable_params_fn,
                    decoder_functions::gettable_params
                ),
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
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_SET_CTX_PARAMS,
                    OSSL_FUNC_decoder_set_ctx_params_fn,
                    decoder_functions::set_ctx_params
                ),
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
                    OSSL_FUNC_decoder_settable_ctx_params_fn,
                    decoder_functions::settable_ctx_params
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
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_EXPORT_OBJECT,
                    OSSL_FUNC_decoder_export_object_fn,
                    decoder_functions::export_object
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispath_table_module::DER_DECODER_FUNCTIONS
    },
};

/// A _DER_ [Decoder][provider-decoder(7ossl)] for _PrivateKeyInfo_
///
/// [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/
#[expect(non_upper_case_globals)]
pub(crate) const DER2PrivateKeyInfo_DECODER: DECODER = DECODER {
    property_definition:
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='PrivateKeyInfo'",
    selection_mask: OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int,
    dispatch_table: {
        mod dispath_table_module {
            #![expect(unused_imports)] // FIXME: get rid of this

            use super::*;
            use bindings::{OSSL_FUNC_decoder_decode_fn, OSSL_FUNC_DECODER_DECODE};
            use bindings::{OSSL_FUNC_decoder_does_selection_fn, OSSL_FUNC_DECODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_decoder_export_object_fn, OSSL_FUNC_DECODER_EXPORT_OBJECT};
            use bindings::{OSSL_FUNC_decoder_freectx_fn, OSSL_FUNC_DECODER_FREECTX};
            use bindings::{OSSL_FUNC_decoder_get_params_fn, OSSL_FUNC_DECODER_GET_PARAMS};
            use bindings::{
                OSSL_FUNC_decoder_gettable_params_fn, OSSL_FUNC_DECODER_GETTABLE_PARAMS,
            };
            use bindings::{OSSL_FUNC_decoder_newctx_fn, OSSL_FUNC_DECODER_NEWCTX};
            use bindings::{OSSL_FUNC_decoder_set_ctx_params_fn, OSSL_FUNC_DECODER_SET_CTX_PARAMS};
            use bindings::{
                OSSL_FUNC_decoder_settable_ctx_params_fn, OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
            };

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_DECODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_GET_PARAMS,
                    OSSL_FUNC_decoder_get_params_fn,
                    decoder_functions::get_params
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_GETTABLE_PARAMS,
                    OSSL_FUNC_decoder_gettable_params_fn,
                    decoder_functions::gettable_params
                ),
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
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_SET_CTX_PARAMS,
                    OSSL_FUNC_decoder_set_ctx_params_fn,
                    decoder_functions::set_ctx_params
                ),
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
                    OSSL_FUNC_decoder_settable_ctx_params_fn,
                    decoder_functions::settable_ctx_params
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
                #[cfg(any())]
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_EXPORT_OBJECT,
                    OSSL_FUNC_decoder_export_object_fn,
                    decoder_functions::export_object
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispath_table_module::DER_DECODER_FUNCTIONS
    },
};

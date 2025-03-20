use super::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_REFERENCE,
    OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use forge::ossl_callback::OSSLCallback;
use forge::osslparams::*;
use libc::{c_int, c_void};
use std::ffi::CString;

struct DecoderContext<'a> {
    provctx: &'a OpenSSLProvider<'a>,
    // worry about ownership later
    properties: Option<CString>,
}

// TODO is this the right value?
const SELECTION_MASK: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int;

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
pub(super) extern "C" fn newctx(vprovctx: *mut c_void) -> *mut c_void {
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
pub(super) extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int {
    trace!(target: log_target!(), "{}", "Called!");

    let _ = params;
    warn!(target: log_target!(), "Ignoring params");

    todo!();
}

#[named]
pub(super) extern "C" fn gettable_params(vprovctx: *mut c_void) -> *const OSSL_PARAM {
    const ERROR_RET: *const OSSL_PARAM = std::ptr::null();
    trace!(target: log_target!(), "{}", "Called!");
    let _provctx: &OpenSSLProvider<'_> = handleResult!(vprovctx.try_into());

    std::ptr::from_ref(&CONST_OSSL_PARAM::END)
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

// based on oqsprov/oqs_decode_der2key.c:oqs_der2key_decode() in the OQS provider
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
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection in decode(): {}", selection);

    let decoderctx: &DecoderContext = handleResult!(vdecoderctx.try_into());
    let cb = handleResult!(OSSLCallback::try_new(data_cb, data_cbarg));

    let bytes = handleResult!(decoderctx.provctx.BIO_read_ex(in_));
    debug!(target: log_target!(), "Read {} bytes in decode()", bytes.len());

    // TODO actually parse the properties, don't just assume it's a public key!
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

    // key bytes get converted to i8 to match the type signature of OSSLParam::new_const_octetstring
    #[allow(unused_mut)]
    let mut key_bytes = key.as_bytes().iter().map(|b| *b as i8).collect::<Box<_>>();

    // TODO this constant comes from core_object.h in openssl: include that file in the wrapper.h
    // file we feed to bindgen in the forge, so a binding gets generated for it
    const OSSL_OBJECT_PKEY: c_int = 2;
    #[allow(unused_mut)]
    let mut object_type = OSSL_OBJECT_PKEY;

    #[allow(unused_mut)]
    let mut keytype_name = c"";

    // TODO clean up this mess
    // These aren't "really" const, we're just using these functions as a shortcut to create
    // OSSL_PARAM structs. the data backing them is mutable, so it should "work" for now.
    // But the compiler can't "see" that; hence the "unused_mut"s explicitly suppressed above.
    let params = &[
        OSSLParam::new_const_int(OSSL_OBJECT_PARAM_TYPE, Some(&object_type)),
        OSSLParam::new_const_utf8string(OSSL_OBJECT_PARAM_DATA_TYPE, Some(&keytype_name)),
        OSSLParam::new_const_octetstring(OSSL_OBJECT_PARAM_REFERENCE, Some(&key_bytes)),
        CONST_OSSL_PARAM::END,
    ];

    cb.call(params.as_ptr() as *const OSSL_PARAM);

    let _ = pw_cb;
    let _ = pw_cbarg;
    warn!(target: log_target!(), "Ignoring pw_cb and pw_cbarg");

    // TODO don't just always return 1
    1
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
    warn!(target: log_target!(), "Ignoring all arguments");

    todo!();
}

// FIXME: this should likely be in openssl_provider_forge, and maybe defined as a trait
pub(crate) struct DECODER {
    pub(crate) property_definition: &'static CStr,
    pub(crate) dispatch_table: &'static [OSSL_DISPATCH],
}

#[expect(non_upper_case_globals)]
pub(crate) const DER2SubjectPublicKeyInfo_DECODER: DECODER = DECODER {
    property_definition:
        c"x.author='QUBIP',x.qubip.adapter='pqclean',input='der',structure='SubjectPublicKeyInfo'",
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
                    decoder_functions::does_selection
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_DECODER_DECODE,
                    OSSL_FUNC_decoder_decode_fn,
                    decoder_functions::decode
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

use crate::adapters::pqclean::MLDSA65::keymgmt_functions::KeyPair;

use super::*;
use bindings::ffi_c_types::*;
use bindings::{
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use forge::operations::{decoder, keymgmt};
use forge::ossl_callback::OSSLCallback;
use forge::osslparams::*;
use keymgmt::selection::Selection;

struct EncoderContext<'a> {
    provctx: &'a OpenSSLProvider<'a>,
}

impl<'a> EncoderContext<'a> {
    pub(super) fn new(provctx: &'a OpenSSLProvider<'a>) -> Self {
        Self { provctx }
    }
}

impl<'a> TryFrom<*mut c_void> for &mut EncoderContext<'a> {
    type Error = OurError;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl TryFrom<*mut c_void> for &mut EncoderContext"
        );
        let ptr = vptr as *mut EncoderContext;
        if ptr.is_null() {
            return Err(anyhow::anyhow!("vptr was null"));
        }
        Ok(unsafe { &mut *ptr })
    }
}

impl<'a> TryFrom<*mut c_void> for &EncoderContext<'a> {
    type Error = OurError;

    #[named]
    fn try_from(vptr: *mut c_void) -> Result<Self, Self::Error> {
        trace!(target: log_target!(), "Called for {}",
        "impl TryFrom<*mut c_void> for &mut EncoderContext"
        );
        let ptr = vptr as *mut EncoderContext;
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

    let encoder_ctx = Box::new(EncoderContext::new(provctx));

    Box::into_raw(encoder_ctx).cast()
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
pub(super) unsafe extern "C" fn freectx(vencoderctx: *mut c_void) {
    trace!(target: log_target!(), "{}", "Called!");

    if !vencoderctx.is_null() {
        let encoder_ctx: Box<EncoderContext> = unsafe { Box::from_raw(vencoderctx.cast()) };
        drop(encoder_ctx);
    }
}

pub(crate) struct PrivateKeyInfo2DER();

use decoder::Decoder;
use decoder::DoesSelection;
use openssl_provider_forge::bindings::OSSL_FUNC_BIO_WRITE_EX;

// the Decoder trait just provides PROPERTY_DEFINITION and DISPATCH_TABLE, so we're
// using it here even though this is an Encoder
impl Decoder for PrivateKeyInfo2DER {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',output='der',structure='PrivateKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_encoder_does_selection_fn, OSSL_FUNC_ENCODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_encoder_encode_fn, OSSL_FUNC_ENCODER_ENCODE};
            use bindings::{OSSL_FUNC_encoder_freectx_fn, OSSL_FUNC_ENCODER_FREECTX};
            use bindings::{OSSL_FUNC_encoder_newctx_fn, OSSL_FUNC_ENCODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_ENCODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_NEWCTX,
                    OSSL_FUNC_encoder_newctx_fn,
                    encoder_functions::newctx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_FREECTX,
                    OSSL_FUNC_encoder_freectx_fn,
                    encoder_functions::freectx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_DOES_SELECTION,
                    OSSL_FUNC_encoder_does_selection_fn,
                    encoder_functions::does_selection_PrivateKeyInfo
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_ENCODE,
                    OSSL_FUNC_encoder_encode_fn,
                    encoder_functions::encodePrivateKeyInfo
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::DER_ENCODER_FUNCTIONS
    };
}

/// Encodes a PrivateKeyInfo to DER
///
/// # Arguments
///
/// ## TODO(🛠️): document arguments
///
/// # Notes
///
/// [`OSSL_FUNC_encoder_encode_fn`][provider-encoder(7ossl)]
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
/// [provider-encoder(7ossl)]: https://docs.openssl.org/master/man7/provider-encoder/
///
/// # Examples
///
/// ## TODO(🛠️): add examples
///
#[named]
pub(super) unsafe extern "C" fn encodePrivateKeyInfo(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection in encodePrivateKeyInfo(): {:#b}", selection);
    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return ERROR_RET;
    }

    let encoderctx: &EncoderContext = handleResult!(vencoderctx.try_into());

    if obj_raw.is_null() {
        error!(target: log_target!(), "No provider-native object passed to encoder");
        return ERROR_RET;
    }

    let keypair: &KeyPair = handleResult!(obj_raw.try_into());
    debug!(target: log_target!(), "Got keypair in encodePrivateKeyInfo(): {:?}", keypair);
    if keypair.private.is_none() {
        error!(target: log_target!(), "Keypair does not contain a private key");
        return ERROR_RET;
    }
    if keypair.public.is_none() {
        error!(target: log_target!(), "Keypair does not contain a public key");
        return ERROR_RET;
    }

    // I'm not 100% sure that this is the right order for them to be in, but we definitely need to
    // include both to get the total number of bytes right
    let mut keypair_bytes = keypair.private.as_ref().unwrap().encode();
    keypair_bytes.extend_from_slice(keypair.public.as_ref().unwrap().encode().as_slice());

    let result = asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            // version (when reading this we discard it)
            w.write_element(&asn1::BigInt::new(&[0]))?;
            // algorithm identifier
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 18))?;
                Ok(())
            }))?;
            // key data
            w.write_element(&asn1::OctetStringEncoded::new(keypair_bytes.as_slice()))?;
            Ok(())
        }))
    });

    let der_bytes = handleResult!(result);
    let der_bytes = der_bytes.as_slice();
    match encoderctx
        .provctx
        .fn_from_core_dispatch(OSSL_FUNC_BIO_WRITE_EX)
    {
        Some(fn_ptr) => {
            let ffi_BIO_write_ex = unsafe {
                std::mem::transmute::<
                    *const (),
                    unsafe extern "C" fn(
                        bio: *mut OSSL_CORE_BIO,
                        data: *const c_void,
                        data_len: usize,
                        written: *mut usize,
                    ) -> c_int,
                >(fn_ptr as _)
            };
            let mut bytes_written: usize = 0;
            let ret = ffi_BIO_write_ex(
                out,
                der_bytes.as_ptr() as *const c_void,
                der_bytes.len(),
                &mut bytes_written,
            );
            return ret;
        }
        None => {
            error!(target: log_target!(), "Unable to retrieve and use BIO_write_ex() upcall pointer");
            return ERROR_RET;
        }
    }
}

impl DoesSelection for PrivateKeyInfo2DER {
    const SELECTION_MASK: Selection = Selection::KEYPAIR;
}

// again, even though this is in the "decoder" module, it works for an encoder too
decoder::make_does_selection_fn!(does_selection_PrivateKeyInfo, PrivateKeyInfo2DER);

// now a bunch of stuff that's mostly the same as above, repeated for the SPKI encoder
pub(crate) struct SubjectPublicKeyInfo2DER();
impl Decoder for SubjectPublicKeyInfo2DER {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',output='der',structure='SubjectPublicKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_encoder_does_selection_fn, OSSL_FUNC_ENCODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_encoder_encode_fn, OSSL_FUNC_ENCODER_ENCODE};
            use bindings::{OSSL_FUNC_encoder_freectx_fn, OSSL_FUNC_ENCODER_FREECTX};
            use bindings::{OSSL_FUNC_encoder_newctx_fn, OSSL_FUNC_ENCODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const DER_ENCODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_NEWCTX,
                    OSSL_FUNC_encoder_newctx_fn,
                    encoder_functions::newctx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_FREECTX,
                    OSSL_FUNC_encoder_freectx_fn,
                    encoder_functions::freectx
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_DOES_SELECTION,
                    OSSL_FUNC_encoder_does_selection_fn,
                    encoder_functions::does_selection_SPKI
                ),
                dispatch_table_entry!(
                    OSSL_FUNC_ENCODER_ENCODE,
                    OSSL_FUNC_encoder_encode_fn,
                    encoder_functions::encodeSPKI
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::DER_ENCODER_FUNCTIONS
    };
}

/// Encodes a SubjectPublicKeyInfo to DER
///
/// # Arguments
///
/// ## TODO(🛠️): document arguments
///
/// # Notes
///
/// [`OSSL_FUNC_encoder_encode_fn`][provider-encoder(7ossl)]
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
/// [provider-encoder(7ossl)]: https://docs.openssl.org/master/man7/provider-encoder/
///
/// # Examples
///
/// ## TODO(🛠️): add examples
///
#[named]
pub(super) unsafe extern "C" fn encodeSPKI(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection in encodeSPKI(): {:#b}", selection);
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int)) == 0 {
        error!(target: log_target!(), "Invalid selection: {selection:#?}");
        return ERROR_RET;
    }

    let encoderctx: &EncoderContext = handleResult!(vencoderctx.try_into());

    if obj_raw.is_null() {
        error!(target: log_target!(), "No provider-native object passed to encoder");
        return ERROR_RET;
    }

    let keypair: &KeyPair = handleResult!(obj_raw.try_into());
    debug!(target: log_target!(), "Got keypair in encodeSPKI(): {:?}", keypair);
    if keypair.public.is_none() {
        error!(target: log_target!(), "Keypair does not contain a public key");
        return ERROR_RET;
    }

    let pubkey_bytes = keypair.public.as_ref().unwrap().encode();

    let result = asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            // algorithm identifier
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 18))?;
                Ok(())
            }))?;
            // key data
            // TODO confirm whether 0 is the right value for padding_bits
            w.write_element(&asn1::BitString::new(pubkey_bytes.as_slice(), 0))?;
            Ok(())
        }))
    });

    let der_bytes = handleResult!(result);
    let der_bytes = der_bytes.as_slice();
    match encoderctx
        .provctx
        .fn_from_core_dispatch(OSSL_FUNC_BIO_WRITE_EX)
    {
        Some(fn_ptr) => {
            let ffi_BIO_write_ex = unsafe {
                std::mem::transmute::<
                    *const (),
                    unsafe extern "C" fn(
                        bio: *mut OSSL_CORE_BIO,
                        data: *const c_void,
                        data_len: usize,
                        written: *mut usize,
                    ) -> c_int,
                >(fn_ptr as _)
            };
            let mut bytes_written: usize = 0;
            let ret = ffi_BIO_write_ex(
                out,
                der_bytes.as_ptr() as *const c_void,
                der_bytes.len(),
                &mut bytes_written,
            );
            return ret;
        }
        None => {
            error!(target: log_target!(), "Unable to retrieve and use BIO_write_ex() upcall pointer");
            return ERROR_RET;
        }
    }
}

impl DoesSelection for SubjectPublicKeyInfo2DER {
    const SELECTION_MASK: Selection = Selection::PUBLIC_KEY;
}

// again, even though this is in the "decoder" module, it works for an encoder too
decoder::make_does_selection_fn!(does_selection_SPKI, SubjectPublicKeyInfo2DER);

use super::keymgmt_functions::KeyPair;

use super::*;
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
use pem;

use super::OurError as EncoderError;
type OurResult<T> = anyhow::Result<T, EncoderError>;

struct EncoderContext<'a> {
    provctx: &'a ProviderInstance<'a>,
}

impl<'a> EncoderContext<'a> {
    pub(super) fn new(provctx: &'a ProviderInstance<'a>) -> Self {
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
    let provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());

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
    let _provctx: &ProviderInstance<'_> = handleResult!(vprovctx.try_into());

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

fn private_key_bytes_to_DER(keypair_bytes: Vec<u8>) -> Result<Vec<u8>, asn1::WriteError> {
    asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            // version (when reading this we discard it)
            w.write_element(&asn1::BigInt::new(&[0]))?;
            // algorithm identifier
            // (here we can't just use super::ALGORITHM_ID_DER, because it's already just a byte
            // array and therefore the asn1 module would encode it as an OCTET STRING)
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&super::OID)?;
                Ok(())
            }))?;
            // key data
            w.write_element(&asn1::OctetStringEncoded::new(keypair_bytes.as_slice()))?;
            Ok(())
        }))
    })
}

pub(crate) struct PrivateKeyInfo2DER();

use openssl_provider_forge::bindings::OSSL_FUNC_BIO_WRITE_EX;
use pkcs8::der::Encode;
use pkcs8::spki::{AlgorithmIdentifier, AlgorithmIdentifierWithOid};
use transcoders::DoesSelection;
use transcoders::Encoder;

impl Encoder for PrivateKeyInfo2DER {
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
                    encoder_functions::encodePrivateKeyInfo2DER
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::DER_ENCODER_FUNCTIONS
    };
}

impl KeyPair<'_> {
    #[named]
    fn to_PrivateKeyInfoDER(&self, _encoderctx: &EncoderContext) -> OurResult<Vec<u8>> {
        trace!(target: log_target!(), "{}", "Called!");

        debug!(target: log_target!(), "Got keypair: {self:?}");
        if self.private.is_none() {
            error!(target: log_target!(), "Keypair does not contain a private key");
            return Err(anyhow!("Keypair does not contain a private key"));
        }
        if self.public.is_none() {
            error!(target: log_target!(), "Keypair does not contain a public key");
            return Err(anyhow!("Keypair does not contain a public key"));
        }

        // unwrap() is safe here because we've already ensured self.private is not None
        let der_sk_bytes = match self.private.as_ref().unwrap().to_DER() {
            Ok(v) => v,
            Err(e) => {
                error!(target: log_target!(), "privkey.to_DER() failed: {e:?}");
                return Err(OurError::from(e));
            }
        };

        let aid = AlgorithmIdentifier {
            oid: super::OID_PKCS8,
            parameters: None,
        };
        let pki = pkcs8::PrivateKeyInfo::new(aid, &der_sk_bytes);
        assert_eq!(pki.version(), pkcs8::Version::V1);

        pki.to_der().map_err(|e| {
            error!(target: log_target!(), "privkey.to_DER() failed: {e:?}");
            anyhow!("Error: {e:?}")
        })
    }

    #[named]
    fn to_SPKIDER(&self, _encoderctx: &EncoderContext) -> OurResult<Vec<u8>> {
        trace!(target: log_target!(), "{}", "Called!");

        debug!(target: log_target!(), "Got keypair: {self:?}");
        if self.public.is_none() {
            error!(target: log_target!(), "Keypair does not contain a public key");
            return Err(anyhow!("Keypair does not contain a public key"));
        }

        // unwrap() is safe here because we've already ensured self.public is not None
        let der_pk_bytes = match self.public.as_ref().unwrap().to_DER() {
            Ok(v) => v,
            Err(e) => {
                error!(target: log_target!(), "pubkey.to_DER() failed: {e:?}");
                return Err(OurError::from(e));
            }
        };
        let bitstring =
            pkcs8::der::asn1::BitString::from_bytes(der_pk_bytes.as_slice()).map_err(|e| {
                error!(target: log_target!(), "Failed to encode bitstring: {e:?}");
                anyhow!("Error: {e:?}")
            })?;

        let aid = AlgorithmIdentifier {
            oid: super::OID_PKCS8,
            parameters: None,
        };
        let spki = pkcs8::spki::SubjectPublicKeyInfoOwned {
            algorithm: aid,
            subject_public_key: bitstring,
        };

        spki.to_der().map_err(|e| {
            error!(target: log_target!(), "spki.to_der() failed: {e:?}");
            anyhow!("Error: {e:?}")
        })
    }
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
pub(super) unsafe extern "C" fn encodePrivateKeyInfo2DER(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const SUCCESS: c_int = 1;
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection: {selection:#b}");
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
    let pki_bytes_der = handleResult!(keypair.to_PrivateKeyInfoDER(encoderctx).map_err(|e| {
        error!(target: log_target!(), "Failed to generate PrivateKeyInfo: {e:?}");
        OurError::from(e)
    }));

    match encoderctx.provctx.BIO_write_ex(out, &pki_bytes_der) {
        Ok(_bytes_written) => {}
        Err(e) => {
            error!(target: log_target!(), "Failure using BIO_write_ex() upcall pointer: {e:?}");
            return ERROR_RET;
        }
    };

    SUCCESS
}

impl DoesSelection for PrivateKeyInfo2DER {
    const SELECTION_MASK: Selection = Selection::KEYPAIR;
}

transcoders::make_does_selection_fn!(
    does_selection_PrivateKeyInfo,
    PrivateKeyInfo2DER,
    ProviderInstance
);

pub(crate) struct PrivateKeyInfo2PEM();

impl Encoder for PrivateKeyInfo2PEM {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',output='pem',structure='PrivateKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_encoder_does_selection_fn, OSSL_FUNC_ENCODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_encoder_encode_fn, OSSL_FUNC_ENCODER_ENCODE};
            use bindings::{OSSL_FUNC_encoder_freectx_fn, OSSL_FUNC_ENCODER_FREECTX};
            use bindings::{OSSL_FUNC_encoder_newctx_fn, OSSL_FUNC_ENCODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const PEM_ENCODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
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
                    encoder_functions::encodePrivateKeyInfo2PEM
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::PEM_ENCODER_FUNCTIONS
    };
}

/// Encodes a PrivateKeyInfo to PEM
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
pub(super) unsafe extern "C" fn encodePrivateKeyInfo2PEM(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const SUCCESS: c_int = 1;
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection: {selection:#b}");
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
    let pki_bytes_der = handleResult!(keypair.to_PrivateKeyInfoDER(encoderctx).map_err(|e| {
        error!(target: log_target!(), "Failed to generate PrivateKeyInfo: {e:?}");
        OurError::from(e)
    }));
    let pki_bytes_der = pki_bytes_der.as_slice();

    let pem = pem::Pem::new("PRIVATE KEY", pki_bytes_der);
    let pem_bytes = pem::encode(&pem).into_bytes();

    match encoderctx.provctx.BIO_write_ex(out, &pem_bytes) {
        Ok(_bytes_written) => {}
        Err(e) => {
            error!(target: log_target!(), "Failure using BIO_write_ex() upcall pointer: {e:?}");
            return ERROR_RET;
        }
    };

    SUCCESS
}

impl DoesSelection for PrivateKeyInfo2PEM {
    const SELECTION_MASK: Selection = Selection::KEYPAIR;
}

// We can use the same does_selection function as PrivateKeyInfo2DER, so there's no need to call
// the make_does_selection_fn macro again.

pub(crate) struct SubjectPublicKeyInfo2DER();
impl Encoder for SubjectPublicKeyInfo2DER {
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
                    encoder_functions::encodeSPKI2DER
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
pub(super) unsafe extern "C" fn encodeSPKI2DER(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const SUCCESS: c_int = 1;
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection: {selection:#b}");
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
    let spki_bytes_der = handleResult!(keypair.to_SPKIDER(encoderctx).map_err(|e| {
        error!(target: log_target!(), "Failed to encode SubjectPublicKeyInfo: {e:?}");
        OurError::from(e)
    }));
    match encoderctx.provctx.BIO_write_ex(out, &spki_bytes_der) {
        Ok(_bytes_written) => {}
        Err(e) => {
            error!(target: log_target!(), "Failure using BIO_write_ex() upcall pointer: {e:?}");
            return ERROR_RET;
        }
    };

    SUCCESS
}

impl DoesSelection for SubjectPublicKeyInfo2DER {
    const SELECTION_MASK: Selection = Selection::PUBLIC_KEY;
}

transcoders::make_does_selection_fn!(
    does_selection_SPKI,
    SubjectPublicKeyInfo2DER,
    ProviderInstance
);

pub(crate) struct SubjectPublicKeyInfo2PEM();
impl Encoder for SubjectPublicKeyInfo2PEM {
    const PROPERTY_DEFINITION: &'static CStr =
        c"x.author='QUBIP',x.qubip.adapter='pqclean',output='pem',structure='SubjectPublicKeyInfo'";

    const DISPATCH_TABLE: &'static [OSSL_DISPATCH] = {
        mod dispatch_table_module {
            use super::*;
            use bindings::{OSSL_FUNC_encoder_does_selection_fn, OSSL_FUNC_ENCODER_DOES_SELECTION};
            use bindings::{OSSL_FUNC_encoder_encode_fn, OSSL_FUNC_ENCODER_ENCODE};
            use bindings::{OSSL_FUNC_encoder_freectx_fn, OSSL_FUNC_ENCODER_FREECTX};
            use bindings::{OSSL_FUNC_encoder_newctx_fn, OSSL_FUNC_ENCODER_NEWCTX};

            // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
            // https://docs.openssl.org/3.2/man7/provider-decoder/
            pub(super) const PEM_ENCODER_FUNCTIONS: &[OSSL_DISPATCH] = &[
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
                    encoder_functions::encodeSPKI2PEM
                ),
                OSSL_DISPATCH::END,
            ];
        }

        dispatch_table_module::PEM_ENCODER_FUNCTIONS
    };
}

/// Encodes a SubjectPublicKeyInfo to PEM
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
pub(super) unsafe extern "C" fn encodeSPKI2PEM(
    vencoderctx: *mut c_void,
    out: *mut OSSL_CORE_BIO,
    obj_raw: *const c_void,
    _obj_abstract: *const OSSL_PARAM,
    selection: c_int,
    _cb: OSSL_PASSPHRASE_CALLBACK,
    _cbarg: *mut c_void,
) -> c_int {
    const SUCCESS: c_int = 1;
    const ERROR_RET: c_int = 0;
    trace!(target: log_target!(), "{}", "Called!");

    debug!(target: log_target!(), "Got selection: {selection:#b}");
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
    let spki_bytes_der = handleResult!(keypair.to_SPKIDER(encoderctx).map_err(|e| {
        error!(target: log_target!(), "Failed to encode SubjectPublicKeyInfo: {e:?}");
        OurError::from(e)
    }));
    let pem = pem::Pem::new("PUBLIC KEY", spki_bytes_der.as_slice());
    let pem_bytes = pem::encode(&pem).into_bytes();
    let pem_bytes = pem_bytes.as_slice();

    match encoderctx.provctx.BIO_write_ex(out, &pem_bytes) {
        Ok(_bytes_written) => {}
        Err(e) => {
            error!(target: log_target!(), "Failure using BIO_write_ex() upcall pointer: {e:?}");
            return ERROR_RET;
        }
    };

    SUCCESS
}

impl DoesSelection for SubjectPublicKeyInfo2PEM {
    const SELECTION_MASK: Selection = Selection::PUBLIC_KEY;
}

// We can use the same does_selection function as SubjectPublicKeyInfo2DER, so there's no need to
// call the make_does_selection_fn macro again.

// generate the plain text encoder
use crate::adapters::common::transcoders::make_pubkey_text_encoder;
make_pubkey_text_encoder!(
    Structureless2Text,
    c"x.author='QUBIP',x.qubip.adapter='pqclean',output='text'"
);

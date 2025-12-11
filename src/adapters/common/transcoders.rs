/// Make a text encoder for a public key.
///
/// The encoder outputs the bytes of the key as colon-separated hex values.
/// This macro takes two arguments:
///
/// - `encoder_struct`, the name of the encoder. The macro will define an empty struct with this
/// name and implement the `Encoder` trait on it.
/// - `property_definition`, which should be an OpenSSL property query string
/// as described in [property(7)](https://docs.openssl.org/3.2/man7/property/).
///
/// This macro should be called in the `encoder_functions` submodule of an algorithm module.
/// The `EncoderContext` and `KeyPair` types must be defined and in scope, and `KeyPair.public`
/// must have the type `Option<PublicKey>`, where `PublicKey` has an `encode` method that returns
/// the key data as something coercible to `&[u8]` (e.g. `Vec<u8>`).
///
/// Like all other encoders, the resulting encoder must be registered in the adapter module's
/// `AdapterContextTrait::register_algorithms` implementation.
///
/// # Example
///
/// ```
/// use crate::adapters::common::transcoders::make_pubkey_text_encoder;
/// make_pubkey_text_encoder!(PubKeyStructureless2Text, c"x.author='QUBIP',x.qubip.adapter='pqclean',output='text'");
/// ```
macro_rules! make_pubkey_text_encoder {
    ($encoder_struct:ident, $property_definition:literal) => {
    pub(crate) struct $encoder_struct();
    impl $crate::forge::operations::transcoders::Encoder for $encoder_struct {
        const PROPERTY_DEFINITION: &'static CStr =
            $property_definition;

        const DISPATCH_TABLE: &'static [$crate::forge::bindings::OSSL_DISPATCH] = {
            mod dispatch_table_module {
                use super::*;
                use $crate::adapters::common::helpers::format_hex_bytes;
                use bindings::{OSSL_FUNC_encoder_does_selection_fn, OSSL_FUNC_ENCODER_DOES_SELECTION};
                use bindings::{OSSL_FUNC_encoder_encode_fn, OSSL_FUNC_ENCODER_ENCODE};
                use bindings::{OSSL_FUNC_encoder_freectx_fn, OSSL_FUNC_ENCODER_FREECTX};
                use bindings::{OSSL_FUNC_encoder_newctx_fn, OSSL_FUNC_ENCODER_NEWCTX};

                // TODO reenable typechecking in dispatch_table_entry macro and make sure these still compile!
                // https://docs.openssl.org/3.2/man7/provider-decoder/
                pub(super) const TEXT_ENCODER_FUNCTIONS: &[$crate::forge::bindings::OSSL_DISPATCH] = &[
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
                        does_selection_text
                    ),
                    dispatch_table_entry!(
                        OSSL_FUNC_ENCODER_ENCODE,
                        OSSL_FUNC_encoder_encode_fn,
                        encodeStructurelessToText
                    ),
                    $crate::forge::bindings::OSSL_DISPATCH::END,
                ];

                #[named]
                pub(super) unsafe extern "C" fn encodeStructurelessToText(
                    vencoderctx: *mut c_void,
                    out: *mut $crate::forge::bindings::OSSL_CORE_BIO,
                    obj_raw: *const c_void,
                    _obj_abstract: *const $crate::forge::bindings::OSSL_PARAM,
                    selection: c_int,
                    _cb: $crate::forge::bindings::OSSL_PASSPHRASE_CALLBACK,
                    _cbarg: *mut c_void,
                ) -> c_int {
                    const SUCCESS: c_int = 1;
                    const ERROR_RET: c_int = 0;
                    trace!(target: log_target!(), "{}", "Called!");

                    debug!(target: log_target!(), "Got selection: {selection:#b}");
                    if (selection & ($crate::forge::bindings::OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int)) == 0 {
                        error!(target: log_target!(), "Invalid selection: {selection:#?}");
                        return ERROR_RET;
                    }

                    let encoderctx: &EncoderContext = $crate::handleResult!(vencoderctx.try_into());

                    if obj_raw.is_null() {
                        error!(target: log_target!(), "No provider-native object passed to encoder");
                        return ERROR_RET;
                    }

                    let keypair: &KeyPair = $crate::handleResult!(obj_raw.try_into());
                    match &keypair.public {
                        Some(key) => {
                            let key_bytes = key.encode();
                            let formatted_key_bytes = format_hex_bytes(15, 4, &key_bytes);
                            let output = format!("Public key bytes:\n{}\n", formatted_key_bytes);
                            let output = handleResult!(CString::new(output));
                            match encoderctx.provctx.BIO_write_ex(out, &output.into_bytes_with_nul()) {
                                Ok(_bytes_written) => {}
                                Err(e) => {
                                    error!(target: log_target!(), "Failure using BIO_write_ex() upcall pointer: {e:?}");
                                    return ERROR_RET;
                                }
                            };
                            return SUCCESS;
                        }
                        None => {
                            error!(target: log_target!(), "No public key");
                            return ERROR_RET;
                        }
                    }
                }

                $crate::forge::operations::transcoders::make_does_selection_fn!(
                    does_selection_text,
                    $encoder_struct,
                    ProviderInstance
                );
            }

            dispatch_table_module::TEXT_ENCODER_FUNCTIONS
        };
    }


    impl $crate::forge::operations::transcoders::DoesSelection for $encoder_struct {
        const SELECTION_MASK: $crate::forge::operations::keymgmt::selection::Selection =
            $crate::forge::operations::keymgmt::selection::Selection::PUBLIC_KEY;
    }


    }
}
pub(crate) use make_pubkey_text_encoder;

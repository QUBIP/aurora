#![allow(unused_imports)]
#![allow(unused_macros)]

macro_rules! algorithm_to_register {
    ($names:expr, $prop:expr, $impl:expr, $description:expr) => {
        $crate::bindings::OSSL_ALGORITHM {
            algorithm_names: $names,
            property_definition: $prop,
            implementation: $impl,
            algorithm_description: $description,
        }
    };
    ($alg:ident, $impl:ident, $prop:expr) => {
        algorithm_to_register!(
            ($alg::NAMES.as_ptr()),
            ($prop.as_ptr()),
            ($alg::$impl.as_ptr()),
            ($alg::DESCRIPTION.as_ptr())
        )
    };
    ($alg:ident, $impl:ident) => {
        algorithm_to_register!($alg, $impl, PROPERTY_DEFINITION)
    };
}
pub(crate) use algorithm_to_register;

macro_rules! decoder_to_register {
    ($alg:ident, $dec_ty:ident) => {{
        use $alg as Alg;
        use $crate::forge::operations::transcoders::Decoder;
        use Alg::$dec_ty as AlgDecoder;
        algorithm_to_register!(
            Alg::NAMES.as_ptr(),
            AlgDecoder::PROPERTY_DEFINITION.as_ptr(),
            AlgDecoder::DISPATCH_TABLE.as_ptr(),
            Alg::DESCRIPTION.as_ptr()
        )
    }};
}
pub(crate) use decoder_to_register;

macro_rules! encoder_to_register {
    ($alg:ident, $dec_ty:ident) => {{
        use $alg as Alg;
        use $crate::forge::operations::transcoders::Encoder;
        use Alg::$dec_ty as AlgEncoder;
        algorithm_to_register!(
            Alg::NAMES.as_ptr(),
            AlgEncoder::PROPERTY_DEFINITION.as_ptr(),
            AlgEncoder::DISPATCH_TABLE.as_ptr(),
            Alg::DESCRIPTION.as_ptr()
        )
    }};
}
pub(crate) use encoder_to_register;

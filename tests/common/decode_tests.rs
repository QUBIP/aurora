use super::openssl;
use super::setup;
use std::path::PathBuf;

#[allow(dead_code)]
pub trait TestParam {
    const ALG_NAME: &str;

    fn openssl_load_sk(data_dir: &PathBuf) {
        let testctx = setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = data_dir.join(Self::ALG_NAME).join("sk.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output =
            openssl::run_openssl_with_aurora(["pkey", "-in", pstr]).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_load_pk(data_dir: &PathBuf) {
        let testctx = setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = data_dir.join(Self::ALG_NAME).join("pk.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output = openssl::run_openssl_with_aurora(["pkey", "-pubin", "-in", pstr])
            .expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_load_cert(data_dir: &PathBuf) {
        let testctx = setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = data_dir.join(Self::ALG_NAME).join("cert.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output =
            openssl::run_openssl_with_aurora(["x509", "-in", pstr]).expect("openssl failed");
        assert!(output.status.success());
    }
}

#[allow(unused_macros)]
macro_rules! generate_tests {
    (data_dir = $data_dir:expr; func = $suffix:ident; $( $alg:ty ),* $(,)?) => {
        $(
            ::paste::paste! {
                #[test]
                #[allow(non_snake_case)]
                fn [<$alg:lower _ $suffix>]() {
                    <$alg>::$suffix($data_dir);
                }
            }
        )*
    }
}
#[allow(unused_imports)]
pub(crate) use generate_tests;

#[allow(unused_macros)]
macro_rules! generate_all_tests {
    ( data_dir = $data_dir:expr; $( $alg:ty ),* $(,)? ) => {
        $crate::common::decode_tests::generate_tests!(data_dir=$data_dir;func=openssl_load_sk; $( $alg ),*);
        $crate::common::decode_tests::generate_tests!(data_dir=$data_dir;func=openssl_load_pk; $( $alg ),*);
        $crate::common::decode_tests::generate_tests!(data_dir=$data_dir;func=openssl_load_cert; $( $alg ),*);
    }
}
#[allow(unused_imports)]
pub(crate) use generate_all_tests;

pub mod test_structs {
    #![allow(dead_code)]

    use super::*;

    pub struct MLDSA44Tests();
    impl TestParam for MLDSA44Tests {
        const ALG_NAME: &str = "mldsa44";
    }

    pub struct MLDSA65Tests();
    impl TestParam for MLDSA65Tests {
        const ALG_NAME: &str = "mldsa65";
    }

    pub struct MLDSA87Tests();
    impl TestParam for MLDSA87Tests {
        const ALG_NAME: &str = "mldsa87";
    }

    pub struct SLHDSASHAKE128fTests();
    impl TestParam for SLHDSASHAKE128fTests {
        const ALG_NAME: &str = "slhdsa_shake_128f";
    }

    pub struct SLHDSASHAKE192fTests();
    impl TestParam for SLHDSASHAKE192fTests {
        const ALG_NAME: &str = "slhdsa_shake_192f";
    }

    pub struct SLHDSASHAKE256sTests();
    impl TestParam for SLHDSASHAKE256sTests {
        const ALG_NAME: &str = "slhdsa_shake_256s";
    }
}

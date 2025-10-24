#![deny(unexpected_cfgs)]

mod common;

use common::openssl;
use std::{path::PathBuf, sync::LazyLock};

static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("openssl35")
});

pub trait TestParam {
    const ALG_DIR: &str;

    fn openssl_load_sk35() {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = DATA_DIR.join(Self::ALG_DIR).join("sk.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output =
            openssl::run_openssl_with_aurora(["pkey", "-in", pstr]).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_load_pk35() {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = DATA_DIR.join(Self::ALG_DIR).join("pk.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output = openssl::run_openssl_with_aurora(["pkey", "-pubin", "-in", pstr])
            .expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_load_cert35() {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let path = DATA_DIR.join(Self::ALG_DIR).join("cert.pem");
        let pstr = path.to_str().expect("Path is not valid UTF-8");

        let output =
            openssl::run_openssl_with_aurora(["x509", "-in", pstr]).expect("openssl failed");
        assert!(output.status.success());
    }
}

mod test_structs {
    #![allow(dead_code)]

    use super::*;

    pub struct MLDSA44Tests();
    impl TestParam for MLDSA44Tests {
        const ALG_DIR: &str = "mldsa44";
    }

    pub struct MLDSA65Tests();
    impl TestParam for MLDSA65Tests {
        const ALG_DIR: &str = "mldsa65";
    }

    pub struct MLDSA87Tests();
    impl TestParam for MLDSA87Tests {
        const ALG_DIR: &str = "mldsa87";
    }

    pub struct SLHDSASHAKE128fTests();
    impl TestParam for SLHDSASHAKE128fTests {
        const ALG_DIR: &str = "slhdsa_shake_128f";
    }

    pub struct SLHDSASHAKE192fTests();
    impl TestParam for SLHDSASHAKE192fTests {
        const ALG_DIR: &str = "slhdsa_shake_192f";
    }

    pub struct SLHDSASHAKE256sTests();
    impl TestParam for SLHDSASHAKE256sTests {
        const ALG_DIR: &str = "slhdsa_shake_256s";
    }
}
use test_structs::*;

#[allow(unused_macros)]
macro_rules! generate_tests {
    ( $suffix:ident, $( $alg:ty ),* $(,)?) => {
        $(
            ::paste::paste! {
                #[test]
                #[allow(non_snake_case)]
                fn [<$alg:lower _ $suffix>]() {
                    <$alg>::$suffix();
                }
            }
        )*
    }
}

#[allow(unused_macros)]
macro_rules! generate_all_tests {
    ( $( $alg:ty ),* $(,)? ) => {
        generate_tests!(openssl_load_sk35, $( $alg ),*);
        generate_tests!(openssl_load_pk35, $( $alg ),*);
        generate_tests!(openssl_load_cert35, $( $alg ),*);
    }
}

#[cfg(feature = "_mldsa")]
generate_all_tests!(MLDSA44Tests, MLDSA65Tests, MLDSA87Tests,);
#[cfg(feature = "_slhdsa")]
generate_all_tests!(
    SLHDSASHAKE128fTests,
    SLHDSASHAKE192fTests,
    SLHDSASHAKE256sTests,
);

mod common;

use common::{openssl, OsString, OutputResult};
use tempfile::tempdir;

#[allow(dead_code)]
static DISABLE_CLEANUP: bool = true;

pub trait TestParam {
    const ALG_NAME: &str;

    /// Verifies that we can generate private keys and parse them
    fn openssl_genprivkey(use_der_format: bool) -> OutputResult {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let alg = Self::ALG_NAME;

        let mut dir = tempdir().expect("Failed to create temp dir");
        dir.disable_cleanup(DISABLE_CLEANUP);
        let dir = dir;

        let (extension, fmt) = match use_der_format {
            true => ("der", "DER"),
            false => ("pem", "PEM"),
        };
        let privkey_path = dir.path().join(format!("{alg:}.privkey.{extension}"));

        let str_privkey_path = privkey_path.to_str().expect("Path is not valid UTF-8");

        // Create a new privkey
        let output = openssl::genpkey(alg, ["-out", str_privkey_path, "-outform", fmt])
            .expect("openssl failed to format the generated private key");
        assert!(
            output.status.success(),
            "openssl failed to generate the private key in {fmt:} format"
        );
        assert!(privkey_path.exists());

        // Parse private key
        assert!(privkey_path.exists());
        let output =
            openssl::run_openssl_with_aurora(["pkey", "-in", str_privkey_path, "-inform", fmt])
                .expect("openssl failed to parse private key");
        assert!(
            output.status.success(),
            "openssl failed to parse private key in {fmt:} format"
        );

        Ok(output)
    }

    /// Verifies that we can generate pubkeys and parse them
    fn openssl_genpubkey(use_der_format: bool) -> OutputResult {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let alg = Self::ALG_NAME;

        let mut dir = tempdir().expect("Failed to create temp dir");
        dir.disable_cleanup(DISABLE_CLEANUP);
        let dir = dir;

        let (extension, fmt) = match use_der_format {
            true => ("der", "DER"),
            false => ("pem", "PEM"),
        };
        let pubkey_path = dir.path().join(format!("{alg:}.pubkey.{extension}"));

        let str_pubkey_path = pubkey_path.to_str().expect("Path is not valid UTF-8");

        // Create a new pubkey
        let output = openssl::genpkey(alg, ["-outpubkey", str_pubkey_path, "-outform", fmt])
            .expect("openssl failed to format the generated public key");
        assert!(
            output.status.success(),
            "openssl failed to generate the public key in {fmt:} format"
        );
        assert!(pubkey_path.exists());

        // Parse public key
        assert!(pubkey_path.exists());
        let output = openssl::run_openssl_with_aurora([
            "pkey",
            "-pubin",
            "-in",
            str_pubkey_path,
            "-inform",
            fmt,
        ])
        .expect("openssl failed to parse public key");
        assert!(
            output.status.success(),
            "openssl failed to parse public key in {fmt:} format"
        );

        Ok(output)
    }

    /// Verifies that we can generate keypairs and parse them
    fn openssl_genpkey(use_der_format: bool) -> OutputResult {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let alg = Self::ALG_NAME;

        let mut dir = tempdir().expect("Failed to create temp dir");
        dir.disable_cleanup(DISABLE_CLEANUP);
        let dir = dir;

        let output = openssl::genpkey(alg, std::iter::empty::<OsString>())
            .expect("openssl failed to generate keypair");
        assert!(output.status.success());

        let (extension, fmt) = match use_der_format {
            true => ("der", "DER"),
            false => ("pem", "PEM"),
        };
        let privkey_path = dir.path().join(format!("{alg:}.privkey.{extension}"));
        let pubkey_path = dir.path().join(format!("{alg:}.pubkey.{extension}"));

        let str_privkey_path = privkey_path.to_str().expect("Path is not valid UTF-8");
        let str_pubkey_path = pubkey_path.to_str().expect("Path is not valid UTF-8");

        // Create a new keypair
        let output = openssl::genpkey(
            alg,
            [
                "-out",
                str_privkey_path,
                "-outpubkey",
                str_pubkey_path,
                "-outform",
                fmt,
            ],
        )
        .expect("openssl failed to format the generated keypair");
        assert!(
            output.status.success(),
            "openssl failed to generate the keypair in {fmt:} format"
        );

        // Parse private key
        assert!(privkey_path.exists());
        let output =
            openssl::run_openssl_with_aurora(["pkey", "-in", str_privkey_path, "-inform", fmt])
                .expect("openssl failed to parse private key");
        assert!(
            output.status.success(),
            "openssl failed to parse private key in {fmt:} format"
        );

        // Parse public key
        assert!(pubkey_path.exists());
        let output = openssl::run_openssl_with_aurora([
            "pkey",
            "-pubin",
            "-in",
            str_pubkey_path,
            "-inform",
            fmt,
        ])
        .expect("openssl failed to parse public key");
        assert!(
            output.status.success(),
            "openssl failed to parse public key in {fmt:} format"
        );

        Ok(output)
    }

    fn openssl_genprivkey_pem() {
        let output = Self::openssl_genprivkey(false).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_genpubkey_pem() {
        let output = Self::openssl_genpubkey(false).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_genprivkey_der() {
        let output = Self::openssl_genprivkey(true).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_genpubkey_der() {
        let output = Self::openssl_genpubkey(true).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_genpkey_pem() {
        let output = Self::openssl_genpkey(false).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_genpkey_der() {
        let output = Self::openssl_genpkey(true).expect("openssl failed");
        assert!(output.status.success());
    }
}

struct MLDSA44Tests();
impl TestParam for MLDSA44Tests {
    const ALG_NAME: &str = "id-ml-dsa-44";
}

struct MLDSA65Tests();
impl TestParam for MLDSA65Tests {
    const ALG_NAME: &str = "id-ml-dsa-65";
}

struct MLDSA87Tests();
impl TestParam for MLDSA87Tests {
    const ALG_NAME: &str = "id-ml-dsa-87";
}

struct MLDSA65ED25519Tests();
impl TestParam for MLDSA65ED25519Tests {
    const ALG_NAME: &str = "mldsa65_ed25519";
}

struct SLHDSASHAKE192fTests();
impl TestParam for SLHDSASHAKE192fTests {
    const ALG_NAME: &str = "id-slh-dsa-shake-192f";
}

use paste::paste;
macro_rules! generate_tests {
    ( $suffix:ident, $( $type:ty ),* ) => {
        $(
            paste! {
                #[test]
                //#[ignore]
                #[allow(non_snake_case)]
                fn [<$type:lower _ $suffix>]() {
                    <$type>::$suffix();
                }
            }
        )*
    }
}

generate_tests!(
    openssl_genprivkey_pem,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);
generate_tests!(
    openssl_genprivkey_der,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);

generate_tests!(
    openssl_genpubkey_pem,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);
generate_tests!(
    openssl_genpubkey_der,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);

generate_tests!(
    openssl_genpkey_pem,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);
generate_tests!(
    openssl_genpkey_der,
    MLDSA65Tests,
    MLDSA87Tests,
    MLDSA44Tests,
    MLDSA65ED25519Tests,
    SLHDSASHAKE192fTests
);

mod common;

use common::{openssl, OutputResult};
use tempfile::tempdir;

#[allow(dead_code)]
static DISABLE_CLEANUP: bool = true;

pub trait TestParam {
    const ALG_NAME: &str;

    /// Verifies that we can generate keys and certs, and parse them
    fn openssl_gencert(use_der_format: bool) -> OutputResult {
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
        let pubkey_path = dir.path().join(format!("{alg:}.pubkey.{extension}"));
        let cert_path = dir.path().join(format!("{alg:}.cert.{extension}"));

        let str_privkey_path = privkey_path.to_str().expect("Path is not valid UTF-8");
        let str_pubkey_path = pubkey_path.to_str().expect("Path is not valid UTF-8");
        let str_cert_path = cert_path.to_str().expect("Path is not valid UTF-8");

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
        .expect("openssl failed");
        assert!(output.status.success());

        assert!(privkey_path.exists());
        assert!(pubkey_path.exists());

        // Request a new self-signed certificate
        let output = openssl::req([
            "-new",
            "-x509",
            "-nodes",
            "-key",
            str_privkey_path,
            "-inform",
            fmt,
            "-out",
            str_cert_path,
            "-outform",
            fmt,
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
        ])
        .expect("openssl failed");
        assert!(output.status.success());
        assert!(cert_path.exists());

        let output = openssl::run_openssl_with_aurora([
            "x509",
            "-in",
            str_cert_path,
            "-inform",
            fmt,
            "-text",
        ])
        .expect("openssl failed");
        assert!(output.status.success());

        let output = openssl::run_openssl_with_aurora([
            "x509",
            "-in",
            str_cert_path,
            "-inform",
            fmt,
            "-noout",
            "-pubkey",
        ])
        .expect("openssl failed");
        assert!(output.status.success());

        #[cfg(any())]
        let output =
            openssl::run_openssl_with_aurora(["verify", "-CAfile", str_cert_path, str_cert_path])
                .expect("openssl failed");
        assert!(output.status.success());

        assert!(dir.path().exists());
        Ok(output)
    }

    fn openssl_gencert_pem() {
        let output = Self::openssl_gencert(false).expect("openssl failed");
        assert!(output.status.success());
    }

    fn openssl_gencert_der() {
        let output = Self::openssl_gencert(true).expect("openssl failed");
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

use paste::paste;
macro_rules! generate_tests {
    ( $suffix:ident, $( $type:ty ),* ) => {
        $(
            paste! {
                #[test]
                #[allow(non_snake_case)]
                fn [<$type:lower _ $suffix>]() {
                    <$type>::$suffix();
                }
            }
        )*
    }
}

generate_tests!(openssl_gencert_der, MLDSA65Tests);
// generate_tests!(
//     openssl_gencert_pem,
//     MLDSA65Tests,
//     MLDSA87Tests,
//     MLDSA44Tests,
//     MLDSA65ED25519Tests
// );
// generate_tests!(
//     openssl_gencert_der,
//     MLDSA65Tests,
//     MLDSA87Tests,
//     MLDSA44Tests,
//     MLDSA65ED25519Tests
// );

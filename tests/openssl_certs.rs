mod common;

use common::{openssl, OutputResult};
use tempfile::tempdir;

static DISABLE_CLEANUP: bool = true;

/// Verifies that we can generate keys and certs, and parse them
fn openssl_gencert(alg: &str, _der_keyoutform: bool, verify: bool) -> OutputResult {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;

    let mut dir = tempdir().expect("Failed to create temp dir");
    dir.disable_cleanup(DISABLE_CLEANUP);
    let dir = dir;

    let privkey_path = dir.path().join(format!("{alg:}.privkey"));
    let pubkey_path = dir.path().join(format!("{alg:}.pubkey"));
    let cert_path = dir.path().join(format!("{alg:}.cert"));

    let str_privkey_path = privkey_path.to_str().expect("Path is not valid UTF-8");
    let str_pubkey_path = pubkey_path.to_str().expect("Path is not valid UTF-8");
    let str_cert_path = cert_path.to_str().expect("Path is not valid UTF-8");

    // Create a new keypair
    let output = openssl::genpkey(
        alg,
        ["-out", str_privkey_path, "-outpubkey", str_pubkey_path],
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
        "-out",
        str_cert_path,
        "-days",
        "30",
        "-subj",
        "/CN=localhost",
    ])
    .expect("openssl failed");
    assert!(output.status.success());
    assert!(cert_path.exists());

    let output = openssl::run_openssl_with_aurora(["x509", "-in", str_cert_path, "-text"])
        .expect("openssl failed");
    assert!(output.status.success());

    if verify {
        let output =
            openssl::run_openssl_with_aurora(["verify", "-CAfile", str_cert_path, str_cert_path])
                .expect("openssl failed");
        assert!(output.status.success());
    }

    assert!(dir.path().exists());
    Ok(output)
}

#[test]
fn openssl_gencert_mldsa44() {
    let alg = "ML-DSA-44";
    let output = openssl_gencert(alg, false, false).unwrap();
    assert!(output.status.success());
}

#[test]
fn openssl_gencert_mldsa65() {
    let alg = "ML-DSA-65";
    let output = openssl_gencert(alg, false, false).unwrap();
    assert!(output.status.success());
}

#[test]
fn openssl_gencert_mldsa87() {
    let alg = "ML-DSA-87";
    let output = openssl_gencert(alg, false, false).unwrap();
    assert!(output.status.success());
}

#[test]
fn openssl_gencert_mldsa65_ed25519() {
    let alg = "mldsa65_ed25519";
    let output = openssl_gencert(alg, false, false).unwrap();
    assert!(output.status.success());
}

#[test]
#[ignore]
fn openssl_gencert_with_verify_mldsa44() {
    let alg = "ML-DSA-44";
    let output = openssl_gencert(alg, false, true).unwrap();
    assert!(output.status.success());
}

#[test]
#[ignore]
fn openssl_gencert_with_verify_mldsa65() {
    let alg = "ML-DSA-65";
    let output = openssl_gencert(alg, false, true).unwrap();
    assert!(output.status.success());
}

#[test]
#[ignore]
fn openssl_gencert_with_verify_mldsa87() {
    let alg = "ML-DSA-87";
    let output = openssl_gencert(alg, false, true).unwrap();
    assert!(output.status.success());
}

#[test]
#[ignore]
fn openssl_gencert_with_verify_mldsa65_ed25519() {
    let alg = "mldsa65_ed25519";
    let output = openssl_gencert(alg, false, true).unwrap();
    assert!(output.status.success());
}

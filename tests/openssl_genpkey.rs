mod common;

use common::{openssl, OsString};

/// Verifies that we can generate mldsa44 keys
#[test]
fn openssl_genpkey_mldsa44() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        openssl::genpkey("mldsa44", std::iter::empty::<OsString>()).expect("openssl failed");
    assert!(output.status.success());
}

/// Verifies that we can generate mldsa65 keys
#[test]
fn openssl_genpkey_mldsa65() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        openssl::genpkey("mldsa65", std::iter::empty::<OsString>()).expect("openssl failed");
    assert!(output.status.success());
}

/// Verifies that we can generate mldsa87 keys
#[test]
fn openssl_genpkey_mldsa87() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        openssl::genpkey("mldsa87", std::iter::empty::<OsString>()).expect("openssl failed");
    assert!(output.status.success());
}

/// Verifies that we can generate mldsa65_ed25519 keys
#[test]
fn openssl_genpkey_mldsa65_ed25519() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output = openssl::genpkey("mldsa65_ed25519", std::iter::empty::<OsString>())
        .expect("openssl failed");
    assert!(output.status.success());
}

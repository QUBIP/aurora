mod common;

use common::{openssl, OsString};

/// Verifies that we can generate mldsa65 keys
#[test]
fn openssl_genpkey_mldsa65() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        openssl::genpkey("mldsa65", std::iter::empty::<OsString>()).expect("openssl failed");
    assert!(output.status.success());
}

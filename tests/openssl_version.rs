#![deny(unexpected_cfgs)]

mod common;

use common::run_openssl;

use regex::Regex;

/// Verifies that we can run the `openssl` binary
#[test]
fn openssl_is_executable() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output = run_openssl(["version"]).expect("openssl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("OpenSSL"));
}

/// Verifies that the `openssl` binary and the loaded library exactly match with the same version
#[test]
fn openssl_bin_version_match_lib() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output = run_openssl(["version"]).expect("openssl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Match two OpenSSL version strings, e.g.:
    // "OpenSSL 3.2.2 4 Jun 2024 (Library: OpenSSL 3.2.2 4 Jun 2024)"
    let full_version_re =
        Regex::new(r"^OpenSSL\s(?P<bin>[^\(]+?)\s*\(Library:\s*OpenSSL\s(?P<lib>.+?)\)\s*$")
            .expect("Invalid regex");

    let captures = full_version_re
        .captures(&stdout)
        .expect(&format!("Unexpected output format: {stdout:?}"));

    let bin_version = captures.name("bin").unwrap().as_str().trim();
    let lib_version = captures.name("lib").unwrap().as_str().trim();

    assert_eq!(
        bin_version, lib_version,
        "Bin version and library version mismatch:\nBin: {bin_version:}\nLib: {lib_version:}"
    );
}

/// Verifies we are running the expected version of OpenSSL
#[test]
fn openssl_expected_version() {
    const EXPECTED_MAJORV: u32 = 3;
    const EXPECTED_MINORV: u32 = 2;

    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output = run_openssl(["version"]).expect("openssl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let version_re =
        Regex::new(r"^OpenSSL\s(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<suffix>[a-z]?)\b")
            .expect("Invalid regex");

    assert!(
        version_re.is_match(&stdout),
        "Unexpected output: {}",
        stdout
    );

    let captures = version_re.captures(&stdout).expect(&format!(
        "Failed to parse OpenSSL version from output: {stdout:?}",
    ));
    let major: u32 = captures["major"].parse().unwrap();
    let minor: u32 = captures["minor"].parse().unwrap();

    assert_eq!(
        major, EXPECTED_MAJORV,
        "Expected major version was {EXPECTED_MAJORV:}, got {major:}"
    );
    assert_eq!(
        minor, EXPECTED_MINORV,
        "Expected minor version was {EXPECTED_MINORV:}, got {minor:}"
    );
}

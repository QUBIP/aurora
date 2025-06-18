mod common;

use common::run_openssl_with_aurora;

use regex::Regex;

/// Verifies that we can load the aurora provider
#[test]
fn openssl_loads_aurora() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        run_openssl_with_aurora(["list", "-providers", "-verbose"]).expect("openssl failed");

    assert!(output.status.success());
}

/// Verifies that aurora reports the expected name
#[test]
fn openssl_aurora_reports_expected_name() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output =
        run_openssl_with_aurora(["list", "-providers", "-verbose"]).expect("openssl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // `(?m)` enables multiline mode, so `^` and `$` work per line
    let name_re = Regex::new(r"(?m)^\s*name:\s*(?P<name>.+)$").expect("Invalid regex");
    let names: Vec<String> = name_re
        .captures_iter(&stdout)
        .map(|caps| caps["name"].to_string())
        .collect();

    // Print all captured names (for debug, optional)
    println!("Captured names: {:?}", names);

    // Assert that at least one name contains "aurora"
    assert!(
        names.iter().any(|name| name.contains("aurora")),
        "Expected at least one provider name to contain 'aurora'"
    );
}

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

#[allow(dead_code)]
#[derive(Debug)]
struct Algorithm {
    names: Vec<String>,
    provider: String,
    props: Vec<String>,
}

impl Algorithm {
    /// Constructs a new instance of [`Algorithm`]
    pub fn new(names: String, provider: String, props: String) -> Self {
        let names = names
            .trim()
            .split(r",")
            .map(|v| v.trim().to_string())
            .collect();
        let provider = provider.trim().to_string();
        let props = props
            .trim()
            .split(",")
            .map(|v| v.trim().to_string())
            .collect();
        Self {
            names,
            provider,
            props,
        }
    }
}

/// List all provided algorithms
#[test]
#[ignore] // ignoring as the regex only catpures encoders/decoders
fn openssl_aurora_list_all_algorithms() {
    let testctx = common::setup().expect("Failed to initialize test setup");
    let _ = testctx;
    let output = run_openssl_with_aurora(["list", "-all-algorithms"]).expect("openssl failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // `(?m)` enables multiline mode, so `^` and `$` work per line
    let algs_re = Regex::new(
        r"(?m)^\s*\{\s*(?P<algnames>.+)\s*\}\s@\s(?P<provider>.+)\s*\((?P<algprops>.+)\s*\)$",
    )
    .expect("Invalid regex");
    let algs: Vec<_> = algs_re
        .captures_iter(&stdout)
        .map(|caps| {
            let names = caps["algnames"].to_string();
            let provider = caps["provider"].to_string();
            let props = caps["algprops"].to_string();
            Algorithm::new(names, provider, props)
        })
        // Filter those provided by libaurora
        .filter(|a| a.provider == "libaurora")
        .collect();

    // Print all captured algorithms (for debug, optional)
    println!("Captured algs: {:?}", algs);

    assert_eq!(
        algs.is_empty(),
        false,
        "aurora should provide at least one algorithm"
    );

    // For each provided algorithm
    for alg in algs {
        // Assert that the algorithm has the expected x.author property
        assert!(
            alg.props.iter().any(|p| p == "x.author='QUBIP'"),
            "Provided algorithm should include the proper `x.author` property: {alg:?}"
        );
        // Assert that the algorithm includes the x.qubip.adapter property
        assert!(
            alg.props.iter().any(|p| p.contains("x.qubip.adapter=")),
            "Provided algorithm should include the `x.qubip.adapter` property: {alg:?}"
        );
    }
}

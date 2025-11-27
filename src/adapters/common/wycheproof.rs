use crate::forge::crypto::signature;
use wycheproof::{
    composite_mldsa_sign, composite_mldsa_verify, mldsa_sign, mldsa_verify, TestResult,
};

pub trait SigAlgVerifyVariant {
    type PublicKey;
    type Signature;

    fn decode_pubkey(bytes: &[u8]) -> anyhow::Result<Self::PublicKey>;

    fn decode_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature>;

    fn verify(
        pubkey: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), signature::Error>;

    fn verify_with_ctx(
        pubkey: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
        ctx: &[u8],
    ) -> Result<(), signature::Error>;
}

// currently unused; since none of our adapters implement verify_with_ctx, we have manual impls for
// the SigAlgVerifyVariant trait that return an error there instead of calling a method
#[macro_export]
macro_rules! impl_sigalg_verify_variant {
    ($variant:ident, $pubkey:ty, $sig:ty) => {
        impl $crate::adapters::common::wycheproof::SigAlgVerifyVariant for $variant {
            type PublicKey = $pubkey;
            type Signature = $sig;

            fn decode_pubkey(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
                <$pubkey>::decode(bytes)
            }

            fn decode_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
                <$sig>::try_from(bytes)
            }

            fn verify(
                pubkey: &Self::PublicKey,
                msg: &[u8],
                sig: &Self::Signature,
            ) -> Result<(), signature::Error> {
                pubkey.verify(msg, sig)
            }

            fn verify_with_ctx(
                pubkey: &Self::PublicKey,
                msg: &[u8],
                sig: &Self::Signature,
                ctx: &[u8],
            ) -> Result<(), signature::Error> {
                pubkey.verify_with_ctx(msg, sig, ctx)
            }
        }
    };
}

/// Borrowed from https://gitlab.com/nisec/qubip/qryptotoken/-/tree/06725b053d280c91a51d8b31775c5360aed9dc50/src/mldsa/wycheproof
/// with some changes, most notably that the tests for error conditions are much shorter because
/// the errors returned from our adapters aren't represented with a principled enum type like the
/// ones in qryptotoken are (so we don't have branching to check against specific error flags).
///
/// Tests are designed to continue running after a failure rather than panicking, so that all
/// failures can be reported together.
pub fn run_mldsa_wycheproof_verify_tests<MlDsaParamSet: SigAlgVerifyVariant>(
    test_name: mldsa_verify::TestName,
) {
    use mldsa_verify::{TestFlag, TestSet};

    let test_set =
        TestSet::load(test_name).unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a public key that
         * is used for all tests in the associated "tests" array. If the public
         * key is invalid, the "tests" array usually contains only one test
         * case explaining the reason for the invalid key.
         *
         * Therefore, when public key decoding fails, we immediately validate
         * that this failure matches the expected outcome for all tests in the
         * group, then skip to the next "testGroup". If the public key is
         * valid, we continue and execute all tests within that group.
         */
        let pubkey_bytes = group.pubkey.as_ref();
        let pubkey = match MlDsaParamSet::decode_pubkey(&pubkey_bytes) {
            Ok(pk) => pk,
            Err(e) => {
                for test in &group.tests {
                    if test.result == TestResult::Invalid
                        && test.flags.contains(&TestFlag::IncorrectPublicKeyLength)
                    {
                        println!(
                            "✅ tcId {}: {} — pubkey decode failed as expected",
                            test.tc_id, test.comment,
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — expected Valid, but pubkey \
                                decode failed: {:?}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }
                /* Jump to next group */
                continue;
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let input_sig = test.sig.as_ref();
            let sig = match MlDsaParamSet::decode_signature(&input_sig) {
                Ok(sig) => sig,
                Err(e) => {
                    let invalid = TestResult::Invalid == test.result;
                    if invalid {
                        println!(
                            "✅ tcId {}: {} — signature decode failed as \
                                expected",
                            test.tc_id, test.comment
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — Expected Valid, but signature \
                                decode failed: {}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                    continue;
                }
            };

            let ctx = test.ctx.as_ref().map_or(&[][..], |c| c.as_ref());

            let result = if !ctx.is_empty() {
                MlDsaParamSet::verify_with_ctx(&pubkey, &msg, &sig, &ctx)
            } else {
                MlDsaParamSet::verify(&pubkey, &msg, &sig)
            };

            let expected = &test.result;
            let passed_case = match (expected, result.is_ok()) {
                (TestResult::Valid, true) => true,
                (TestResult::Invalid, false) => true,
                _ => false,
            };
            if passed_case {
                println!("✅ tcId {}: {}", test.tc_id, test.comment);
                passed += 1;
            } else {
                println!(
                    "❌ tcId {}: {} — expected {:?}, got {:?}",
                    test.tc_id, test.comment, expected, result
                );
                failed += 1;
            }
            continue;
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof test cases failed");
}

pub fn run_composite_mldsa_wycheproof_verify_tests<CompositeMlDsaParamSet: SigAlgVerifyVariant>(
    test_name: composite_mldsa_verify::TestName,
) {
    let test_set = composite_mldsa_verify::TestSet::load(test_name)
        .unwrap_or_else(|e| panic!("Failed to load verify test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a public key that
         * is used for all tests in the associated "tests" array. If the public
         * key is invalid, the "tests" array usually contains only one test
         * case explaining the reason for the invalid key.
         *
         * Therefore, when public key decoding fails, we immediately validate
         * that this failure matches the expected outcome for all tests in the
         * group, then skip to the next "testGroup". If the public key is
         * valid, we continue and execute all tests within that group.
         */
        let pubkey_bytes = group.pubkey.as_ref();
        let pubkey = match CompositeMlDsaParamSet::decode_pubkey(&pubkey_bytes) {
            Ok(pk) => pk,
            Err(e) => {
                for test in &group.tests {
                    if test.result == TestResult::Invalid {
                        println!(
                            "✅ tcId {}: {} — pubkey decode failed as expected",
                            test.tc_id, test.comment,
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — expected Valid, but pubkey \
                                decode failed: {:?}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }
                /* Jump to next group */
                continue;
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let input_sig = test.sig.as_ref();
            let sig = match CompositeMlDsaParamSet::decode_signature(&input_sig) {
                Ok(sig) => sig,
                Err(e) => {
                    let invalid = TestResult::Invalid == test.result;
                    if invalid {
                        println!(
                            "✅ tcId {}: {} — signature decode failed as \
                                expected",
                            test.tc_id, test.comment
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — Expected Valid, but signature \
                                decode failed: {}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                    continue;
                }
            };

            // the composite tests don't have a `ctx` field, so we always use the "plain" `verify`
            let result = CompositeMlDsaParamSet::verify(&pubkey, &msg, &sig);

            let expected = &test.result;
            let passed_case = match (expected, result.is_ok()) {
                (TestResult::Valid, true) => true,
                (TestResult::Invalid, false) => true,
                _ => false,
            };
            if passed_case {
                println!("✅ tcId {}: {}", test.tc_id, test.comment);
                passed += 1;
            } else {
                println!(
                    "❌ tcId {}: {} — expected {:?}, got {:?}",
                    test.tc_id, test.comment, expected, result
                );
                failed += 1;
            }
            continue;
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof test cases failed");
}

pub trait SigAlgSignVariant {
    type PrivateKey;
    type Signature;

    /* It's up to the implementation to decide what to do with these bytes, e.g. in the ML-DSA case
     * whether to treat them as a seed or as an expanded key.
     */
    fn decode_privkey(bytes: &[u8]) -> anyhow::Result<Self::PrivateKey>;

    fn try_sign(
        privkey: &Self::PrivateKey,
        msg: &[u8],
        //deterministic: bool,
    ) -> Result<Self::Signature, signature::Error>;

    fn try_sign_with_ctx(
        privkey: &Self::PrivateKey,
        msg: &[u8],
        ctx: &[u8],
        //deterministic: bool,
    ) -> Result<Self::Signature, signature::Error>;

    fn encode_signature(sig: &Self::Signature) -> Vec<u8>;
}

/// Borrowed from https://gitlab.com/nisec/qubip/qryptotoken/-/tree/06725b053d280c91a51d8b31775c5360aed9dc50/src/mldsa/wycheproof
/// with some changes, most notably that the tests for error conditions are much shorter because
/// the errors returned from our adapters aren't represented with a principled enum type like the
/// ones in qryptotoken are (so we don't have branching to check against specific error flags).
///
/// Tests are designed to continue running after a failure rather than panicking, so that all
/// failures can be reported together.
pub fn run_mldsa_wycheproof_sign_tests<MlDsaParamSet: SigAlgSignVariant>(
    test_name: mldsa_sign::TestName,
    deterministic: bool,
) {
    use mldsa_sign::{TestFlag, TestSet};

    let test_set =
        TestSet::load(test_name).unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a private key that
         * is used for all tests in the associated "tests" array. If the
         * private key is invalid, the "tests" array usually contains only one
         * test case explaining the reason for the invalid key.
         *
         * Therefore, when private key decoding fails (or generation from seed)
         * we immediately validate that this failure matches the expected
         * outcome for all tests in the group, then skip to the next
         * "testGroup". If the private key is valid, we continue and execute
         * all tests within that group.
         */

        /* Use privseed first, otherwise fallback to privkey */
        let priv_bytes = group
            .privseed
            .as_ref()
            .or(group.privkey.as_ref())
            .map(|b| b.as_slice().to_vec())
            .unwrap_or_else(|| panic!("Neither privateKey nor privateSeed present in test group"));

        let privkey = match MlDsaParamSet::decode_privkey(&priv_bytes) {
            Ok(sk) => sk,
            Err(e) => {
                for test in &group.tests {
                    if test.result == TestResult::Invalid {
                        if test.flags.iter().any(|&flag| {
                            flag == TestFlag::IncorrectPrivateKeyLength
                                || flag == TestFlag::InvalidPrivateKey
                        }) {
                            println!(
                                "✅ tcId {}: {} — privkey decode failed \
                                        as expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "❌ tcId {}: {} — expected Invalid (with acceptable privkey), \
                                        but privkey decode failed: {:?}",
                                test.tc_id, test.comment, e
                            );
                            failed += 1;
                        }
                    } else {
                        println!(
                            "❌ tcId {}: {} — expected Valid, but privkey \
                                    decode failed: {:?}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }
                /* Jump to next group */
                continue;
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let ctx = test.ctx.as_ref().map_or(&[][..], |c| c.as_ref());
            let sig_res = if ctx.is_empty() {
                MlDsaParamSet::try_sign(&privkey, &msg)
            } else {
                MlDsaParamSet::try_sign_with_ctx(&privkey, &msg, &ctx)
            };

            match (&sig_res, test.result) {
                (Err(_), TestResult::Invalid) => {
                    println!(
                        "✅ tcId {}: {} — signing failed as expected",
                        test.tc_id, test.comment
                    );
                    passed += 1;
                }
                (Err(e), TestResult::Valid) => {
                    println!(
                        "❌ tcId {}: {} — expected Valid, but signing \
                            failed: {:?}",
                        test.tc_id, test.comment, e
                    );
                    failed += 1;
                }
                (Ok(_), TestResult::Invalid) => {
                    println!(
                        "❌ tcId {}: {} — expected Invalid, but signing \
                            succeeded",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
                (Ok(sig), TestResult::Valid) => {
                    if deterministic {
                        let expected = test.sig.as_ref();
                        let actual = MlDsaParamSet::encode_signature(sig);
                        if actual == expected {
                            println!(
                                "✅ tcId {}: {} — signature matches expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "❌ tcId {}: {} — signature mismatch",
                                test.tc_id, test.comment
                            );
                            failed += 1;
                        }
                    } else {
                        println!("✅ tcId {}: {}", test.tc_id, test.comment);
                        passed += 1;
                    }
                }
                _ => {
                    println!(
                        "❌ tcId {}: {} — 'Acceptable' case not covered",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
            }
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof signing test cases failed");
}

pub fn run_composite_mldsa_wycheproof_sign_tests<CompositeMlDsaParamSet: SigAlgSignVariant>(
    test_name: composite_mldsa_sign::TestName,
    deterministic: bool,
) {
    let test_set = composite_mldsa_sign::TestSet::load(test_name)
        .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
    let mut passed = 0;
    let mut failed = 0;

    for group in test_set.test_groups {
        /*
         * In Wycheproof, each entry in "testGroups" defines a private key that
         * is used for all tests in the associated "tests" array. If the
         * private key is invalid, the "tests" array usually contains only one
         * test case explaining the reason for the invalid key.
         *
         * Therefore, when private key decoding fails (or generation from seed)
         * we immediately validate that this failure matches the expected
         * outcome for all tests in the group, then skip to the next
         * "testGroup". If the private key is valid, we continue and execute
         * all tests within that group.
         */

        let privkey = match CompositeMlDsaParamSet::decode_privkey(&group.privkey) {
            Ok(sk) => sk,
            Err(e) => {
                for test in &group.tests {
                    if test.result == TestResult::Invalid {
                        println!(
                            "✅ tcId {}: {} — privkey decode failed \
                                as expected",
                            test.tc_id, test.comment
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ tcId {}: {} — expected Valid, but privkey \
                                decode failed: {:?}",
                            test.tc_id, test.comment, e
                        );
                        failed += 1;
                    }
                }
                /* Jump to next group */
                continue;
            }
        };

        for test in &group.tests {
            let msg = test.msg.as_ref();
            let sig_res = CompositeMlDsaParamSet::try_sign(&privkey, &msg);

            match (&sig_res, test.result) {
                (Err(_), TestResult::Invalid) => {
                    println!(
                        "✅ tcId {}: {} — signing failed as expected",
                        test.tc_id, test.comment
                    );
                    passed += 1;
                }
                (Err(e), TestResult::Valid) => {
                    println!(
                        "❌ tcId {}: {} — expected Valid, but signing \
                            failed: {:?}",
                        test.tc_id, test.comment, e
                    );
                    failed += 1;
                }
                (Ok(_), TestResult::Invalid) => {
                    println!(
                        "❌ tcId {}: {} — expected Invalid, but signing \
                            succeeded",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
                (Ok(sig), TestResult::Valid) => {
                    if deterministic {
                        let expected = test.sig.as_ref();
                        let actual = CompositeMlDsaParamSet::encode_signature(sig);
                        if actual == expected {
                            println!(
                                "✅ tcId {}: {} — signature matches expected",
                                test.tc_id, test.comment
                            );
                            passed += 1;
                        } else {
                            println!(
                                "❌ tcId {}: {} — signature mismatch",
                                test.tc_id, test.comment
                            );
                            failed += 1;
                        }
                    } else {
                        println!("✅ tcId {}: {}", test.tc_id, test.comment);
                        passed += 1;
                    }
                }
                _ => {
                    println!(
                        "❌ tcId {}: {} — 'Acceptable' case not covered",
                        test.tc_id, test.comment
                    );
                    failed += 1;
                }
            }
        }
    }

    println!(
        "\n✔️ Passed: {passed} | ❌ Failed: {failed} | Total: {}",
        passed + failed
    );
    assert_eq!(failed, 0, "Some Wycheproof signing test cases failed");
}

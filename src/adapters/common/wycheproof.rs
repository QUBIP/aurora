use crate::forge::crypto::signature;
use wycheproof::composite_mldsa_verify;
use wycheproof::mldsa_verify;
use wycheproof::TestResult;

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
    let test_set = mldsa_verify::TestSet::load(test_name)
        .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
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
        .unwrap_or_else(|e| panic!("Failed to load sign test set: {e}"));
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

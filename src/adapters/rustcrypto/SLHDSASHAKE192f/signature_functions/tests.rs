use super::*;

struct TestCTX<'a> {
    provctx: OpenSSLProvider<'a>,
}

fn setup<'a>() -> Result<TestCTX<'a>, OurError> {
    use crate::tests::new_provctx_for_testing;

    crate::tests::common::setup()?;

    let provctx = new_provctx_for_testing();

    let testctx = TestCTX { provctx };

    Ok(testctx)
}

#[test]
fn test_sign() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate a keypair
    let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    let mut sigctx = SignatureContext::new(&provctx);
    // sign a message
    let msg: [u8; 5] = [1, 2, 3, 4, 5];
    sigctx.sign_init(&keypair).unwrap();
    let signature = sigctx.try_sign(&msg).unwrap();
    assert_eq!(signature.encoded_len(), SIGNATURE_LEN);
    // (this test succeeds if we've gotten this far without anything exploding)
}

#[test]
fn test_sign_and_verify_success() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate keypair
    let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    let mut sigctx = SignatureContext::new(&provctx);
    // sign a message with it
    let msg: [u8; 5] = [1, 2, 3, 4, 5];
    sigctx.sign_init(&keypair).unwrap();
    let signature = sigctx.try_sign(&msg).unwrap();
    assert_eq!(signature.encoded_len(), SIGNATURE_LEN);
    let sig_bytes = signature.to_bytes();
    let sig_bytes = sig_bytes.as_ref();
    let sig = Signature::try_from(sig_bytes).unwrap();
    // verify the signature
    sigctx.verify_init(&keypair).unwrap();
    assert!(sigctx.verify(&msg, &sig).is_ok());
}

#[test]
fn test_sign_and_verify_wrong_key_failure() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate keypair
    let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    let mut sigctx = SignatureContext::new(&provctx);
    // sign a message with it
    let msg: [u8; 5] = [1, 2, 3, 4, 5];
    sigctx.sign_init(&keypair).unwrap();
    let signature = sigctx.try_sign(&msg).unwrap();
    let sig = signature.to_bytes();
    let sig = sig.as_ref();
    let sig = Signature::try_from(sig).unwrap();
    // generate another keypair
    let other_keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    // confirm that verification with the new key fails
    sigctx.verify_init(&other_keypair).unwrap();
    let ret = sigctx.verify(&msg, &sig);
    assert!(ret.is_err());
}

#[test]
fn test_sign_and_verify_tampered_sig_failure() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate keypair
    let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    let mut sigctx = SignatureContext::new(&provctx);
    // sign a message with it
    let msg: [u8; 5] = [1, 2, 3, 4, 5];
    sigctx.sign_init(&keypair).unwrap();
    let signature = sigctx.try_sign(&msg).unwrap().to_bytes();
    let signature = signature.as_ref();
    let mut mut_sig = [0; SIGNATURE_LEN];
    mut_sig.copy_from_slice(signature);
    // flip a bit in the signature
    mut_sig[2] = std::ops::BitXor::bitxor(mut_sig[2], 1u8);
    let sig = Signature::try_from(mut_sig.as_slice()).unwrap();
    // confirm that verification fails
    sigctx.verify_init(&keypair).unwrap();
    assert!(sigctx.verify(&msg, &sig).is_err());
}

#[test]
fn test_sign_and_verify_tampered_msg_failure() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate keypair
    let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
    let mut sigctx = SignatureContext::new(&provctx);
    // sign a message with it
    let msg: [u8; 5] = [1, 2, 3, 4, 5];
    sigctx.sign_init(&keypair).unwrap();
    let signature = sigctx.try_sign(&msg).unwrap().to_bytes();
    let signature = signature.as_ref();
    let sig = Signature::try_from(signature).unwrap();
    // construct a different message of the same length
    let other_msg: [u8; 5] = [1, 2, 3, 8, 5];
    // confirm that verification fails
    sigctx.verify_init(&keypair).unwrap();
    assert!(sigctx.verify(&other_msg, &sig).is_err());
    // construct a longer message with the same initial contents
    let other_msg: [u8; 6] = [1, 2, 3, 4, 5, 6];
    // confirm that verification fails
    sigctx.verify_init(&keypair).unwrap();
    assert!(sigctx.verify(&other_msg, &sig).is_err());
}

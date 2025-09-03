use super::*;

struct TestCTX<'a> {
    provctx: OpenSSLProvider<'a>,
}

mod helpers {
    use super::*;

    pub(super) fn setup<'a>() -> Result<TestCTX<'a>, OurError> {
        use crate::tests::new_provctx_for_testing;

        crate::tests::common::setup()?;

        let provctx = new_provctx_for_testing();

        let testctx = TestCTX { provctx };

        Ok(testctx)
    }

    #[named]
    pub(super) fn generate_keypair<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
    ) -> KeyPair<'provctx> {
        log::info!(target: log_target!(), "Generating keypair");
        let keypair = KeyPair::generate_new(&provctx).expect("Failed to generate keypair");
        return keypair;
    }

    #[named]
    pub(super) fn create_sigctx<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
    ) -> SignatureContext<'provctx> {
        log::info!(target: log_target!(), "Creating new SignatureContext");
        let sigctx = SignatureContext::new(&provctx);

        return sigctx;
    }

    #[named]
    pub(super) fn sign_msg<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        keypair: &'provctx KeyPair<'provctx>,
        msg: &[u8],
    ) -> SignatureBytes {
        let mut sigctx = create_sigctx(provctx);

        log::info!(target: log_target!(), "Initializing the new SignatureContext");
        sigctx
            .sign_init(&keypair)
            .expect("Failed to initialize the SignatureContext for signing");

        log::info!(target: log_target!(), "Signing message");
        let signature = sigctx.try_sign(&msg).expect("Failed to sign the message");
        assert_eq!(signature.encoded_len(), SIGNATURE_LEN);

        let sig_bytes = signature.to_bytes();

        return sig_bytes;
    }

    #[named]
    pub(super) fn verify_msg<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        keypair: &'provctx KeyPair<'provctx>,
        msg_to_verify: &[u8],
        signature: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Decoding signature");
        assert_eq!(signature.len(), SIGNATURE_LEN);
        let signature = Signature::try_from(signature).expect("Failed to decode the signature");

        log::info!(target: log_target!(), "Creating new SignatureContext");
        let mut sigctx = create_sigctx(provctx);

        log::info!(target: log_target!(), "Initializing the new SignatureContext");
        sigctx
            .verify_init(&keypair)
            .expect("Failed to initialize the SignatureContext for verification");

        let res = sigctx.verify(msg_to_verify, &signature);
        log::info!(target: log_target!(), "Verify result: ${res:?}");

        return res;
    }

    #[named]
    pub(super) fn verify_happy_path<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        original_keypair: &'provctx KeyPair<'provctx>,
        original_msg: &[u8],
        original_sig: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Testing verify happy path");
        let res = helpers::verify_msg(provctx, original_keypair, original_msg, original_sig);
        assert!(res.is_ok());

        Ok(())
    }

    #[named]
    pub(super) fn verify_wrong_key_failure<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        original_keypair: &'provctx KeyPair<'provctx>,
        original_msg: &[u8],
        original_sig: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Generating another keypair");
        let other_keypair = helpers::generate_keypair(provctx);

        // ensure the keys are diffeent
        let original_pubkey = original_keypair
            .public
            .as_ref()
            .expect("Missing public key");
        let other_pubkey = other_keypair.public.as_ref().expect("Missing public key");
        assert_ne!(original_pubkey, other_pubkey);

        // confirm that verification fails
        let res = helpers::verify_msg(provctx, &other_keypair, original_msg, original_sig);
        assert!(res.is_err());

        Ok(())
    }

    #[named]
    pub(super) fn verify_tampered_sig_failure<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        original_keypair: &'provctx KeyPair<'provctx>,
        original_msg: &[u8],
        original_sig: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Deriving a tampered version of the signature");
        let mut tampered_sig = [0; SIGNATURE_LEN];
        tampered_sig.copy_from_slice(original_sig);
        // flip a bit in the signature
        tampered_sig[2] = std::ops::BitXor::bitxor(tampered_sig[2], 1u8);

        assert_ne!(original_sig, &tampered_sig);

        // confirm that verification fails
        let res = helpers::verify_msg(provctx, original_keypair, original_msg, &tampered_sig);
        assert!(res.is_err());

        Ok(())
    }

    #[named]
    pub(super) fn verify_tampered_msg_failure<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        original_keypair: &'provctx KeyPair<'provctx>,
        original_msg: &[u8],
        original_sig: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Deriving a tampered version of the message");
        let mut tampered_msg = original_msg.to_owned();
        // flip a bit in the message
        tampered_msg[2] = std::ops::BitXor::bitxor(tampered_msg[2], 1u8);

        assert_ne!(original_msg, &tampered_msg);

        // confirm that verification fails
        let res = helpers::verify_msg(provctx, original_keypair, &tampered_msg, original_sig);
        assert!(res.is_err());

        Ok(())
    }

    #[named]
    pub(super) fn verify_longer_msg_failure<'provctx>(
        provctx: &'provctx OpenSSLProvider<'provctx>,
        original_keypair: &'provctx KeyPair<'provctx>,
        original_msg: &[u8],
        original_sig: &[u8],
    ) -> Result<(), signature::Error> {
        log::info!(target: log_target!(), "Deriving a tampered version of the message");
        let mut tampered_msg = original_msg.to_owned();
        tampered_msg.extend_from_slice(&[0x0, 0xDE, 0xAD, 0xC0, 0xDE]);

        assert_ne!(original_msg, &tampered_msg);

        // confirm that verification fails
        let res = helpers::verify_msg(provctx, original_keypair, &tampered_msg, original_sig);
        assert!(res.is_err());

        Ok(())
    }
}

use helpers::setup;

#[test]
#[named]
fn test_signature_algorithm() {
    let testctx = setup().expect("Failed to initialize test setup");
    let provctx = testctx.provctx;

    // generate a keypair
    let keypair = helpers::generate_keypair(&provctx);

    // sign a message
    let msg: [u8; 5] = [1, 2, 3, 4, 5];

    let signature = helpers::sign_msg(&provctx, &keypair, &msg);
    let signature = signature.as_ref();
    assert!(signature.len() > 0);

    log::info!(target: log_target!(), "Testing verification happy path");
    helpers::verify_happy_path(&provctx, &keypair, &msg, signature).unwrap();

    log::info!(target: log_target!(), "Testing verification with wrong key");
    helpers::verify_wrong_key_failure(&provctx, &keypair, &msg, signature).unwrap();

    log::info!(target: log_target!(), "Testing verification with tampered signature");
    helpers::verify_tampered_sig_failure(&provctx, &keypair, &msg, signature).unwrap();

    log::info!(target: log_target!(), "Testing verification with tampered message (bitflip)");
    helpers::verify_tampered_msg_failure(&provctx, &keypair, &msg, signature).unwrap();

    log::info!(target: log_target!(), "Testing verification with tampered message (append bytes)");
    helpers::verify_longer_msg_failure(&provctx, &keypair, &msg, signature).unwrap();
}

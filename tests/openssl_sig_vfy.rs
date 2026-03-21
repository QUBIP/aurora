#![deny(unexpected_cfgs)]

mod common;

use common::openssl;
use std::fs;
use std::io;
use std::path::Path;
use std::{path::PathBuf, sync::LazyLock};
use tempfile::tempdir;

#[allow(dead_code)]
static DISABLE_CLEANUP: bool = false;

static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
});

/// Read `input`, flip one bit, and write the result to `output`.
///
/// `byte_index` selects which byte to modify.
/// `bit_index` must be in 0..8 and selects which bit inside that byte.
///
/// Example:
/// - bit_index = 0 flips the least-significant bit
/// - bit_index = 7 flips the most-significant bit
pub fn bitflip_file<P: AsRef<Path>>(
    input: P,
    output: P,
    byte_index: usize,
    bit_index: u8,
) -> io::Result<()> {
    if bit_index >= 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bit_index must be in 0..8",
        ));
    }

    let mut data = fs::read(&input)?;

    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input file is empty",
        ));
    }

    if byte_index >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "byte_index {} out of range for file of length {}",
                byte_index,
                data.len()
            ),
        ));
    }

    data[byte_index] ^= 1u8 << bit_index;
    fs::write(output, data)
}

pub trait TestParam {
    const ALG_NAME: &str;

    fn filename_privkey(prefix: Option<&str>, extension: &str) -> String {
        let prefix = prefix.map(|p| format!("{p}.")).unwrap_or_default();
        format!("{}.{prefix}privkey.{extension}", Self::ALG_NAME)
    }
    fn filename_pubkey(prefix: Option<&str>, extension: &str) -> String {
        let prefix = prefix.map(|p| format!("{p}.")).unwrap_or_default();
        format!("{}.{prefix}pubkey.{extension}", Self::ALG_NAME)
    }

    /// Verifies that we can generate keys and drive sign/verify from the CLI
    fn openssl_sig_vfy() -> io::Result<()> {
        let testctx = common::setup().expect("Failed to initialize test setup");
        let _ = testctx;

        let alg = Self::ALG_NAME;

        let mut dir = tempdir().expect("Failed to create temp dir");
        dir.disable_cleanup(DISABLE_CLEANUP);
        let dir = dir;

        let (extension, fmt) = ("pem", "PEM");

        let privkey_path = dir.path().join(Self::filename_privkey(None, extension));
        let pubkey_path = dir.path().join(Self::filename_pubkey(None, extension));
        let other_pubkey_path = dir
            .path()
            .join(Self::filename_pubkey(Some("other"), extension));

        let good_msg_path = DATA_DIR.join("good.txt");
        assert!(good_msg_path.exists());
        let wrong_msg_path = DATA_DIR.join("wrong.txt");
        assert!(wrong_msg_path.exists());
        let good_sig_path = dir.path().join("good.sig");
        let wrong_sig_path = dir.path().join("wrong.sig");

        let str_privkey_path = privkey_path.to_str().expect("Path is not valid UTF-8");
        let str_pubkey_path = pubkey_path.to_str().expect("Path is not valid UTF-8");
        let str_other_pubkey_path = other_pubkey_path.to_str().expect("Path is not valid UTF-8");
        let str_good_msg_path = good_msg_path.to_str().expect("Path is not valid UTF-8");
        let str_wrong_msg_path = wrong_msg_path.to_str().expect("Path is not valid UTF-8");
        let str_good_sig_path = good_sig_path.to_str().expect("Path is not valid UTF-8");
        let str_wrong_sig_path = wrong_sig_path.to_str().expect("Path is not valid UTF-8");

        // Create a new keypair
        let output = openssl::genpkey(
            alg,
            [
                "-out",
                str_privkey_path,
                "-outpubkey",
                str_pubkey_path,
                "-outform",
                fmt,
            ],
        )
        .expect("openssl failed");
        assert!(output.status.success());

        assert!(privkey_path.exists());
        assert!(pubkey_path.exists());

        // Sign the good msg
        let output = openssl::run_openssl_with_aurora([
            "pkeyutl",
            "-sign",
            "-inkey",
            str_privkey_path,
            "-in",
            str_good_msg_path,
            "-out",
            str_good_sig_path,
        ])
        .expect("openssl failed");
        assert!(output.status.success());
        assert!(good_sig_path.exists());

        // Verify the good signature against the good msg
        let output = openssl::run_openssl_with_aurora([
            "pkeyutl",
            "-verify",
            "-in",
            str_good_msg_path,
            "-pubin",
            "-inkey",
            str_pubkey_path,
            "-sigfile",
            str_good_sig_path,
        ])
        .expect("openssl failed");
        assert!(output.status.success());

        // Verify the good signature against the wrong msg
        let output = openssl::run_openssl_with_aurora([
            "pkeyutl",
            "-verify",
            "-in",
            str_wrong_msg_path,
            "-pubin",
            "-inkey",
            str_pubkey_path,
            "-sigfile",
            str_good_sig_path,
        ])
        .expect("openssl failed");
        assert!(
            !output.status.success(),
            "Verifying against the wrong message should fail"
        );

        // Create another distinct public key
        let output = openssl::genpkey(alg, ["-outpubkey", str_other_pubkey_path, "-outform", fmt])
            .expect("openssl failed");
        assert!(output.status.success());
        assert!(other_pubkey_path.exists());

        // Verify the good signature against the good msg, but using the wrong public key
        let output = openssl::run_openssl_with_aurora([
            "pkeyutl",
            "-verify",
            "-in",
            str_good_msg_path,
            "-pubin",
            "-inkey",
            str_other_pubkey_path,
            "-sigfile",
            str_good_sig_path,
        ])
        .expect("openssl failed");
        assert!(
            !output.status.success(),
            "Verifying against the wrong public key should fail"
        );

        // Tamper with the good signature
        bitflip_file(&good_sig_path, &wrong_sig_path, 3, 3)
            .expect("Failed to tamper with the good signature");
        assert!(&wrong_sig_path.exists());

        // Verify the tampered signature against the good msg
        let output = openssl::run_openssl_with_aurora([
            "pkeyutl",
            "-verify",
            "-in",
            str_good_msg_path,
            "-pubin",
            "-inkey",
            str_pubkey_path,
            "-sigfile",
            str_wrong_sig_path,
        ])
        .expect("openssl failed");
        assert!(
            !output.status.success(),
            "Verifying a tampered signature should fail"
        );

        Ok(())
    }
}

mod test_structs {
    #![allow(dead_code)]

    use super::*;

    pub struct MLDSA44Tests();
    impl TestParam for MLDSA44Tests {
        const ALG_NAME: &str = "id-ml-dsa-44";
    }

    pub struct MLDSA65Tests();
    impl TestParam for MLDSA65Tests {
        const ALG_NAME: &str = "id-ml-dsa-65";
    }
    pub struct MLDSA87Tests();
    impl TestParam for MLDSA87Tests {
        const ALG_NAME: &str = "id-ml-dsa-87";
    }

    pub struct MLDSA44ED25519Tests();
    impl TestParam for MLDSA44ED25519Tests {
        const ALG_NAME: &str = "mldsa44_ed25519";
    }

    pub struct MLDSA65ED25519Tests();
    impl TestParam for MLDSA65ED25519Tests {
        const ALG_NAME: &str = "mldsa65_ed25519";
    }

    pub struct SLHDSASHAKE128fTests();
    impl TestParam for SLHDSASHAKE128fTests {
        const ALG_NAME: &str = "id-slh-dsa-shake-128f";
    }

    pub struct SLHDSASHAKE192fTests();
    impl TestParam for SLHDSASHAKE192fTests {
        const ALG_NAME: &str = "id-slh-dsa-shake-192f";
    }

    pub struct SLHDSASHAKE256sTests();
    impl TestParam for SLHDSASHAKE256sTests {
        const ALG_NAME: &str = "id-slh-dsa-shake-256s";
    }
}
use test_structs::*;

#[allow(unused_macros)]
macro_rules! generate_tests {
    ( $suffix:ident, $( $type:ty ),* $(,)?) => {
        $(
            ::paste::paste! {
                #[test]
                #[allow(non_snake_case)]
                fn [<$type:lower _ $suffix>]() {
                    <$type>::$suffix().expect("Test failed");
                }
            }
        )*
    }
}

#[allow(unused_macros)]
macro_rules! generate_all_tests {
    ( $( $alg:ty ),* $(,)? ) => {
        generate_tests!(openssl_sig_vfy, $( $alg ),*);
    }
}

#[cfg(feature = "_mldsa")]
generate_all_tests!(MLDSA44Tests, MLDSA65Tests, MLDSA87Tests,);

#[cfg(feature = "_composite_mldsa_eddsa")]
generate_all_tests!(MLDSA44ED25519Tests, MLDSA65ED25519Tests,);

#[cfg(feature = "_slhdsa")]
generate_all_tests!(
    SLHDSASHAKE128fTests,
    SLHDSASHAKE192fTests,
    SLHDSASHAKE256sTests,
);

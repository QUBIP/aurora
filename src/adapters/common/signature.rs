//! This module provides the implementation of the `Signature` type and related utilities
//! for handling digital signatures.
//!
//! This builds on top of the [RustCrypto `signature` traits](https://docs.rs/signature/latest/signature/).
//!
//! ## Types
//!
//! - `Signature`
//! - `SignatureBytes`
//!
//! ## Traits
//!
//! - `SignatureEncoding`: The `Signature` type implements the `SignatureEncoding` trait,
//!   which defines the associated type `Repr` as `SignatureBytes`. This allows for encoding
//!   and decoding operations to be performed on the signature.
//!
//! ## Error Handling
//!
//! The module uses the `OurError` type to represent errors that may occur during operations
//! such as signature conversion. For example, if the length of a byte slice does not match
//! `SIGNATURE_LEN`, an error is logged and returned.
//!
//! ## Logging
//!
//! The module uses the `log` crate to log errors, such as when a signature length mismatch
//! occurs. Ensure that a logger is properly configured in your application to capture these logs.

use super::*;
pub use forge::crypto::signature::{Error, SignatureEncoding, Signer, Verifier};

/// The main type representing a digital signature. It implements the `TryFrom`
/// trait for conversion from a byte slice (`&[u8]`) and ensures that the input length matches
/// the expected signature length (`SIGNATURE_LEN`).
///
/// The `Signature` type represents a digital signature, which is stored as a heap-allocated
/// vector of bytes (`Vec<u8>`). This design choice allows for flexibility in handling
/// signatures of varying lengths, though the expected length is defined by the constant
/// `SIGNATURE_LEN`.
#[derive(Clone, PartialEq)]
pub struct Signature {
    bytes: Vec<u8>, // Using Vec<u8> instead of [u8; SIGNATURE_LEN] for heap allocation
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = OurError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != SIGNATURE_LEN {
            log::error!(
                "Signature is expected to be exactly {SIGNATURE_LEN} bytes, got {}",
                value.len()
            );
            return Err(anyhow!(
                "signature length mismatch, got {}, expected {SIGNATURE_LEN}",
                value.len()
            ));
        }

        let bytes = value.to_vec();
        Ok(Signature { bytes })
    }
}

/// A wrapper around `Vec<u8>` that provides an abstraction for working
/// with the raw bytes of a signature. It implements the `AsRef<[u8]>` trait for convenient
/// access to the underlying byte slice.
#[derive(Clone)]
pub struct SignatureBytes(Vec<u8>);

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryInto<SignatureBytes> for Signature {
    type Error = OurError;

    fn try_into(self) -> Result<SignatureBytes, Self::Error> {
        Ok(SignatureBytes(self.bytes))
    }
}

impl SignatureEncoding for Signature {
    type Repr = SignatureBytes;
}

/// Verify the provided message bytestring using `Self` (typically a public key)
pub(crate) trait VerifierWithCtx<S> {
    /// Use `Self` to verify that the provided signature for a given message
    /// bytestring is authentic.
    fn verify_with_ctx(&self, msg: &[u8], signature: &S, ctx: &[u8]) -> Result<(), Error>;
}

/// Sign the provided message bytestring using `Self`, returning a digital signature.
pub(crate) trait SignerWithCtx<S> {
    /// Sign the given message and return a digital signature
    fn sign_with_ctx(&self, msg: &[u8], ctx: &[u8]) -> S {
        self.try_sign_with_ctx(msg, ctx)
            .expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    fn try_sign_with_ctx(&self, msg: &[u8], ctx: &[u8]) -> Result<S, Error>;
}

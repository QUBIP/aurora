use function_name::named;

/// pqclean does not provide support to derive the public key from an
/// expanded private key so we resort to
/// RustCrypto/signatures/ml-dsa to work around this
use ml_dsa as foreign_mldsa_module;

pub(super) const ML_DSA_SEED_SIZE: usize = 32;

pub(super) type MlDsaSeed = [u8; ML_DSA_SEED_SIZE];

pub(super) trait SupportedMlDsaSecretKey: pqcrypto_traits::sign::SecretKey {
    type ForeignParamSet: foreign_mldsa_module::MlDsaParams;
    type PublicKey;
}

impl SupportedMlDsaSecretKey for pqcrypto_mldsa::mldsa44::SecretKey {
    type ForeignParamSet = foreign_mldsa_module::MlDsa44;
    type PublicKey = pqcrypto_mldsa::mldsa44::PublicKey;
}
impl SupportedMlDsaSecretKey for pqcrypto_mldsa::mldsa65::SecretKey {
    type ForeignParamSet = foreign_mldsa_module::MlDsa65;
    type PublicKey = pqcrypto_mldsa::mldsa65::PublicKey;
}
impl SupportedMlDsaSecretKey for pqcrypto_mldsa::mldsa87::SecretKey {
    type ForeignParamSet = foreign_mldsa_module::MlDsa87;
    type PublicKey = pqcrypto_mldsa::mldsa87::PublicKey;
}

/// Derive the matching public key from a secret key
#[named]
pub(super) fn derive_mldsa_public_key<T>(sk: &T) -> Option<T::PublicKey>
where
    T: SupportedMlDsaSecretKey,
    <T as SupportedMlDsaSecretKey>::PublicKey: pqcrypto_traits::sign::PublicKey,
{
    let encoded_sk = <T as pqcrypto_traits::sign::SecretKey>::as_bytes(sk);
    let encoded_sk = match encoded_sk.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "Failed to encode secret key to bytes: {e:?}");
            return None;
        }
    };
    let csk = <foreign_mldsa_module::SigningKey<T::ForeignParamSet>>::decode(encoded_sk);
    let cpk = csk.verifying_key();
    let pk_bytes = cpk.encode();
    let pk_bytes = pk_bytes.as_slice();

    let res =
        <<T as SupportedMlDsaSecretKey>::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
            pk_bytes,
        );
    match res {
        Ok(pk) => Some(pk),
        Err(e) => {
            error!(target: log_target!(), "Failed to derive the public key from the inner private key: {e:?}");
            return None;
        }
    }
}

/// Derive the expanded secret key from a seed
#[named]
pub(super) fn derive_mldsa_secret_key_from_seed<T>(seed: &MlDsaSeed) -> Option<T>
where
    T: SupportedMlDsaSecretKey,
{
    let foreign_key =
        <foreign_mldsa_module::SigningKey<T::ForeignParamSet>>::from_seed(seed.into());
    let key_bytes = foreign_key.encode();
    let res = <T as pqcrypto_traits::sign::SecretKey>::from_bytes(&key_bytes);
    match res {
        Ok(sk) => Some(sk),
        Err(e) => {
            error!(target: log_target!(), "Failed to derive the expanded private key from the seed: {e:?}");
            return None;
        }
    }
}

const VALIDATE_PRIVKEY_DECODING_VIA_FOREIGN_MODULE: bool = true;

/// Use the foreign_mldsa_module to decode bytes as a secret key
#[named]
fn foreign_decode_mldsa_secret_key<T>(
    bytes: &[u8],
) -> std::thread::Result<
    foreign_mldsa_module::SigningKey<<T as SupportedMlDsaSecretKey>::ForeignParamSet>,
>
where
    T: SupportedMlDsaSecretKey,
{
    // The `<foreign_mldsa_module::SigningKey<T::ForeignParamSet>>::decode(a)`
    // call can panic internally.
    // We want to catch those errors, and handle them gracefully, hence catch_unwind
    use std::panic::{self, catch_unwind, AssertUnwindSafe};

    let a = match bytes.try_into() {
        Ok(a) => a,
        Err(e) => {
            error!(target: log_target!(), "Found wrong length when decoding EncodedPrivateKey: {e:?}");
            return Err(Box::new(e));
        }
    };

    // Before calling decode within the catch_unwind block, we temporarily
    // replace the `panic` hook, to avoid polluting the output.

    // Take the current hook so we can restore it later
    let prev_hook = panic::take_hook();

    panic::set_hook(Box::new(|info| {
        trace!(target: log_target!(), "Caught panic: {}", info);
    }));

    let result = catch_unwind(AssertUnwindSafe(|| {
        <foreign_mldsa_module::SigningKey<T::ForeignParamSet>>::decode(a)
    }));

    // Restore the previous hook
    panic::set_hook(prev_hook);

    result
}

/// Decode the bytes as a secret key, deriving from seed if necessary
#[named]
pub(super) fn decode_mldsa_secret_key<T>(bytes: &[u8]) -> Option<T>
where
    T: SupportedMlDsaSecretKey,
{
    // First we check if the EncodedBytes match the expected length for seed format
    match TryInto::<&MlDsaSeed>::try_into(bytes) {
        Ok(seed) => {
            return derive_mldsa_secret_key_from_seed(seed);
        }
        Err(_) => (),
    }

    // If we reach here, the key was not in seed format, and we exepct an
    // expanded private key

    if VALIDATE_PRIVKEY_DECODING_VIA_FOREIGN_MODULE {
        // Currently PQClean is too lenient in parsing private keys.
        // We use a more strict-on-decode foreign module to try and correctly decode
        // the input, before asking PQClean to decode.
        let foreign_result = foreign_decode_mldsa_secret_key::<T>(bytes);

        match foreign_result {
            Ok(_) => (), // we discard the foreign module object
            Err(e) => {
                if let Some(s) = e.downcast_ref::<&str>() {
                    error!(target: log_target!(), "Failed to decode the EncodedPrivateKey: {s}");
                } else if let Some(s) = e.downcast_ref::<String>() {
                    error!(target: log_target!(), "Failed to decode the EncodedPrivateKey: {s}");
                } else {
                    error!(target: log_target!(), "Failed to decode the EncodedPrivateKey");
                }
                return None;
            }
        }

        // Finally if we reached this point we know that the `foreign_mldsa_module`
        // could decode the EncodedPrivateKey. We can proceed with the lenient
        // decoding routines of PQClean
    }

    T::from_bytes(bytes).ok()
}

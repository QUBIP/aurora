use function_name::named;

/// pqclean does not provide support to derive the public key from an
/// expanded private key so we resort to
/// RustCrypto/signatures/ml-dsa to work around this
use ml_dsa as foreign_mldsa_module;

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
pub(super) fn derive_public_key<T>(sk: &T) -> Option<T::PublicKey>
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
pub(super) fn derive_secret_key_from_seed<T>(seed: &[u8]) -> Option<T>
where
    T: SupportedMlDsaSecretKey,
{
    let seed: &[u8; 32] = seed.try_into().ok()?;
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

/// Decode the bytes as a secret key, deriving from seed if necessary
pub(super) fn decode_secret_key<T>(bytes: &[u8]) -> Option<T>
where
    T: SupportedMlDsaSecretKey,
{
    derive_secret_key_from_seed(bytes).or_else(|| T::from_bytes(bytes).ok())
}

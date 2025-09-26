use function_name::named;

/// pqclean does not provide support to derive the public key from an
/// expanded private key so we resort to
/// RustCrypto/signatures/ml-dsa to work around this
use ml_dsa as foreign_module;

pub(super) trait SupportedSecretKey: pqcrypto_traits::sign::SecretKey {
    type ForeignParamSet: foreign_module::MlDsaParams;
    type PublicKey;
}

impl SupportedSecretKey for pqcrypto_mldsa::mldsa44::SecretKey {
    type ForeignParamSet = foreign_module::MlDsa44;
    type PublicKey = pqcrypto_mldsa::mldsa44::PublicKey;
}
impl SupportedSecretKey for pqcrypto_mldsa::mldsa65::SecretKey {
    type ForeignParamSet = foreign_module::MlDsa65;
    type PublicKey = pqcrypto_mldsa::mldsa65::PublicKey;
}
impl SupportedSecretKey for pqcrypto_mldsa::mldsa87::SecretKey {
    type ForeignParamSet = foreign_module::MlDsa87;
    type PublicKey = pqcrypto_mldsa::mldsa87::PublicKey;
}

/// Derive the matching public key from a secret key
#[named]
pub(super) fn derive_public_key<T>(sk: &T) -> Option<T::PublicKey>
where
    T: SupportedSecretKey,
    <T as SupportedSecretKey>::PublicKey: pqcrypto_traits::sign::PublicKey,
{
    let encoded_sk = <T as pqcrypto_traits::sign::SecretKey>::as_bytes(sk);
    let encoded_sk = match encoded_sk.try_into() {
        Ok(p) => p,
        Err(e) => {
            error!(target: log_target!(), "Failed to encode secret key to bytes: {e:?}");
            return None;
        }
    };
    let csk = <foreign_module::SigningKey<T::ForeignParamSet>>::decode(encoded_sk);
    let cpk = csk.verifying_key();
    let pk_bytes = cpk.encode();
    let pk_bytes = pk_bytes.as_slice();

    let res =
        <<T as SupportedSecretKey>::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
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

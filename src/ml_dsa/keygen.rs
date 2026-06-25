//! FIPS 204 ML-DSA key generation.

use crate::encoding::{
    PublicKeyHash, Rho, SECRET_KEY_SEED_BYTES, SecretKeySeed, pk_encode, sk_encode,
};
use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::sampling::{ExpandASeed, ExpandSSeed, expand_a, expand_s};
use crate::xof::shake256;

use super::algebra::{multiply_ntt_matrix_vector, power2_round_vector};
use super::random::random_bytes;
use super::types::{KeyPair, PrivateKey, PublicKey};

/// Number of random bytes consumed by `ML-DSA.KeyGen`.
pub const KEYGEN_SEED_BYTES: usize = 32;

/// Generates an ML-DSA key pair using the operating system RBG.
///
/// This is the external FIPS 204 `ML-DSA.KeyGen()` path: it samples a fresh
/// 32-byte seed `ξ` and then delegates to [`keygen_from_seed`].
pub fn keygen(parameter_set: ParameterSet) -> DilithiumResult<KeyPair> {
    keygen_from_seed(parameter_set, random_bytes::<KEYGEN_SEED_BYTES>()?)
}

/// Generates an ML-DSA key pair from the FIPS 204 seed `ξ`.
///
/// This is `ML-DSA.KeyGen_internal(ξ)` from Algorithm 6. It is deterministic
/// and is intended for KATs, tests, and future RFC 9881 seed-only private-key
/// import. Normal applications should use [`keygen`].
pub fn keygen_from_seed(
    parameter_set: ParameterSet,
    seed: [u8; KEYGEN_SEED_BYTES],
) -> DilithiumResult<KeyPair> {
    let expanded_seed = expand_keygen_seed(parameter_set, seed);
    let (rho, rho_prime, secret_key_seed) = split_keygen_seed(&expanded_seed);

    let a_hat = expand_a(ExpandASeed::new(rho), parameter_set)?;
    let (s1, s2) = expand_s(ExpandSSeed::new(rho_prime), parameter_set)?;
    let t = multiply_ntt_matrix_vector(&a_hat, &s1, parameter_set)?.checked_add(&s2)?;
    let (t1, t0) = power2_round_vector(&t, parameter_set)?;

    let public_key_bytes = pk_encode(rho, &t1, parameter_set)?;
    let tr = public_key_hash(&public_key_bytes);
    let private_key_bytes = sk_encode(rho, secret_key_seed, tr, &s1, &s2, &t0, parameter_set)?;

    Ok(KeyPair::new(
        PublicKey::from_raw(parameter_set, public_key_bytes)?,
        PrivateKey::from_raw(parameter_set, private_key_bytes)?,
    ))
}

fn expand_keygen_seed(parameter_set: ParameterSet, seed: [u8; KEYGEN_SEED_BYTES]) -> Vec<u8> {
    let mut input = Vec::with_capacity(KEYGEN_SEED_BYTES + 2);
    input.extend_from_slice(&seed);
    input.push(parameter_set.core.k as u8);
    input.push(parameter_set.core.l as u8);
    shake256(&input, 128)
}

fn split_keygen_seed(expanded_seed: &[u8]) -> (Rho, [u8; 64], SecretKeySeed) {
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut secret_key_seed = [0u8; SECRET_KEY_SEED_BYTES];

    rho.copy_from_slice(&expanded_seed[..32]);
    rho_prime.copy_from_slice(&expanded_seed[32..96]);
    secret_key_seed.copy_from_slice(&expanded_seed[96..128]);

    (rho, rho_prime, secret_key_seed)
}

pub(crate) fn public_key_hash(public_key: &[u8]) -> PublicKeyHash {
    let digest = shake256(public_key, 64);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&digest);
    tr
}

//! FIPS 204 ML-DSA key generation.
//!
//! This module implements the external `ML-DSA.KeyGen()` entry point and the
//! deterministic internal `ML-DSA.KeyGen_internal(ξ)` algorithm.
//!
//! The internal flow is:
//!
//! ```text
//! (ρ, ρ′, K) = H(ξ || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
//! Â          = ExpandA(ρ)
//! (s₁, s₂)   = ExpandS(ρ′)
//! t          = Âs₁ + s₂
//! (t₁, t₀)   = Power2Round(t)
//! pk         = pkEncode(ρ, t₁)
//! tr         = H(pk, 64)
//! sk         = skEncode(ρ, K, tr, s₁, s₂, t₀)
//! ```
//!
//! The public key carries only `ρ` and `t₁`: `ρ` lets verifiers reconstruct the
//! public matrix `Â`, while `t₁` is the high-order part of `t`. The expanded
//! private key keeps the signing material `K`, `s₁`, `s₂`, and `t₀`, plus `tr`
//! so signing can compute `μ = H(tr || M′, 64)` without hashing the public key
//! again.

use crate::encoding::{Rho, SECRET_KEY_SEED_BYTES, SecretKeySeed, pk_encode, sk_encode};
use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::sampling::{ExpandASeed, ExpandSSeed, expand_a, expand_s};
use crate::xof::shake256;

use super::random::random_bytes;
use super::types::{KeyPair, PrivateKey, PublicKey};

/// Number of random bytes consumed by `ML-DSA.KeyGen`.
pub const KEYGEN_SEED_BYTES: usize = 32;

const EXPANDED_KEYGEN_SEED_BYTES: usize = 128;

type ExpandedKeygenSeedBytes = [u8; EXPANDED_KEYGEN_SEED_BYTES];

/// FIPS 204 seed `ξ` consumed by `ML-DSA.KeyGen_internal`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeygenSeed([u8; KEYGEN_SEED_BYTES]);

impl KeygenSeed {
    /// Builds the seed from its fixed-size byte representation.
    pub const fn new(bytes: [u8; KEYGEN_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size byte representation.
    pub const fn bytes(self) -> [u8; KEYGEN_SEED_BYTES] {
        self.0
    }

    /// Borrows the fixed-size byte representation.
    pub const fn as_bytes(&self) -> &[u8; KEYGEN_SEED_BYTES] {
        &self.0
    }
}

impl From<[u8; KEYGEN_SEED_BYTES]> for KeygenSeed {
    fn from(bytes: [u8; KEYGEN_SEED_BYTES]) -> Self {
        Self::new(bytes)
    }
}

impl From<KeygenSeed> for [u8; KEYGEN_SEED_BYTES] {
    fn from(seed: KeygenSeed) -> Self {
        seed.bytes()
    }
}

/// Typed split of `H(ξ || k || l, 128)` for `ML-DSA.KeyGen_internal`.
struct ExpandedKeygenSeed {
    /// Public matrix seed `ρ`, later included in `pk`.
    rho: Rho,
    /// Secret-vector seed `ρ′`, consumed by `ExpandS`.
    rho_prime: ExpandSSeed,
    /// FIPS signing seed `K`, later included in the expanded private key.
    secret_key_seed: SecretKeySeed,
}

impl ExpandedKeygenSeed {
    /// Derives and splits the FIPS 204 KeyGen seed stream.
    fn derive(parameter_set: ParameterSet, seed: KeygenSeed) -> Self {
        Self::from_bytes(expand_keygen_seed(parameter_set, seed))
    }

    /// Splits the 128-byte KeyGen seed stream into `ρ`, `ρ′`, and `K`.
    ///
    /// The byte layout is:
    ///
    /// ```text
    /// 0..32    → ρ
    /// 32..96   → ρ′
    /// 96..128  → K
    /// ```
    fn from_bytes(expanded_seed: ExpandedKeygenSeedBytes) -> Self {
        let mut rho = [0u8; 32];
        let mut rho_prime = [0u8; 64];
        let mut secret_key_seed = [0u8; SECRET_KEY_SEED_BYTES];

        rho.copy_from_slice(&expanded_seed[..32]);
        rho_prime.copy_from_slice(&expanded_seed[32..96]);
        secret_key_seed.copy_from_slice(&expanded_seed[96..128]);

        Self {
            rho,
            rho_prime: ExpandSSeed::new(rho_prime),
            secret_key_seed,
        }
    }

    /// Returns `ρ` typed for `ExpandA`.
    fn expand_a_seed(&self) -> ExpandASeed {
        ExpandASeed::new(self.rho)
    }
}

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
///
/// The seed is first expanded into `ρ`, `ρ′`, and `K`. `ρ` deterministically
/// reconstructs the public NTT-domain matrix `Â`; `ρ′` samples the short secret
/// vectors `s₁` and `s₂`; `K` is stored in the private key for later signing
/// mask derivation.
///
/// The core relation computed here is `t = Âs₁ + s₂`. `Power2Round` then splits
/// `t` into `(t₁, t₀)`: `t₁` is encoded into the raw public key, while `t₀`
/// remains in the expanded private key. Finally, `tr = H(pk, 64)` is stored in
/// the private key so signatures are bound to the public key through
/// `μ = H(tr || M′, 64)`.
pub fn keygen_from_seed(
    parameter_set: ParameterSet,
    seed: impl Into<KeygenSeed>,
) -> DilithiumResult<KeyPair> {
    let expanded_seed = ExpandedKeygenSeed::derive(parameter_set, seed.into());

    let a_hat = expand_a(expanded_seed.expand_a_seed(), parameter_set)?;
    let (s1, s2) = expand_s(expanded_seed.rho_prime, parameter_set)?;
    let t = a_hat
        .multiply_vector(&s1, parameter_set)?
        .checked_add(&s2)?;
    let (t1, t0) = t.power2_round(parameter_set)?;

    let public_key_bytes = pk_encode(expanded_seed.rho, &t1, parameter_set)?;
    let public_key = PublicKey::from_raw(parameter_set, public_key_bytes)?;
    let tr = public_key.hash();
    let private_key_bytes = sk_encode(
        expanded_seed.rho,
        expanded_seed.secret_key_seed,
        tr,
        &s1,
        &s2,
        &t0,
        parameter_set,
    )?;

    KeyPair::new(
        public_key,
        PrivateKey::from_raw(parameter_set, private_key_bytes)?,
    )
}

/// Expands `ξ` into the 128-byte FIPS 204 KeyGen seed stream.
///
/// FIPS domain-separates parameter sets by hashing
/// `ξ || IntegerToBytes(k, 1) || IntegerToBytes(l, 1)`. The output is later
/// split into `ρ`, `ρ′`, and `K`.
fn expand_keygen_seed(parameter_set: ParameterSet, seed: KeygenSeed) -> ExpandedKeygenSeedBytes {
    let mut input = Vec::with_capacity(KEYGEN_SEED_BYTES + 2);
    input.extend_from_slice(seed.as_bytes());
    input.push(parameter_set.core.k as u8);
    input.push(parameter_set.core.l as u8);

    let digest = shake256(&input, EXPANDED_KEYGEN_SEED_BYTES);
    let mut expanded_seed = [0u8; EXPANDED_KEYGEN_SEED_BYTES];
    expanded_seed.copy_from_slice(&digest);
    expanded_seed
}

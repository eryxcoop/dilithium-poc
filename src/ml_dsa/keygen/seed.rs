//! Seed derivation for FIPS 204 `ML-DSA.KeyGen_internal`.

use crate::encoding::{Rho, SECRET_KEY_SEED_BYTES, SecretKeySeed};
use crate::params::ParameterSet;
use crate::sampling::{ExpandASeed, ExpandSSeed};
use crate::xof::shake256;

/// Number of random bytes consumed by `ML-DSA.KeyGen`.
pub(super) const KEYGEN_SEED_BYTES: usize = 32;

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

    /// Expands `ξ` into the 128-byte FIPS 204 KeyGen seed stream.
    ///
    /// FIPS domain-separates parameter sets by hashing
    /// `ξ || IntegerToBytes(k, 1) || IntegerToBytes(l, 1)`. The output is
    /// later split into `ρ`, `ρ′`, and `K`.
    fn expand(self, parameter_set: ParameterSet) -> ExpandedKeygenSeedBytes {
        let mut input = Vec::with_capacity(KEYGEN_SEED_BYTES + 2);
        input.extend_from_slice(self.as_bytes());
        input.push(parameter_set.core.k as u8);
        input.push(parameter_set.core.l as u8);

        let digest = shake256(&input, EXPANDED_KEYGEN_SEED_BYTES);
        let mut expanded_seed = [0u8; EXPANDED_KEYGEN_SEED_BYTES];
        expanded_seed.copy_from_slice(&digest);
        expanded_seed
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
pub(super) struct ExpandedKeygenSeed {
    /// Public matrix seed `ρ`, later included in `pk`.
    pub(super) rho: Rho,
    /// Secret-vector seed `ρ′`, consumed by `ExpandS`.
    pub(super) rho_prime: ExpandSSeed,
    /// FIPS signing seed `K`, later included in the expanded private key.
    pub(super) secret_key_seed: SecretKeySeed,
}

impl ExpandedKeygenSeed {
    /// Derives and splits the FIPS 204 KeyGen seed stream.
    pub(super) fn derive(parameter_set: ParameterSet, seed: KeygenSeed) -> Self {
        Self::from_bytes(seed.expand(parameter_set))
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
    pub(super) fn expand_a_seed(&self) -> ExpandASeed {
        ExpandASeed::new(self.rho)
    }
}

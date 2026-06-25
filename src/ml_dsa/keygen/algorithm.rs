//! Associated `KeyPair` constructors for FIPS 204 KeyGen.

use crate::encoding::{pk_encode, sk_encode};
use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::sampling::{expand_a, expand_s};

use super::super::random::random_bytes;
use super::super::types::{KeyPair, PrivateKey, PublicKey};
use super::seed::{ExpandedKeygenSeed, KEYGEN_SEED_BYTES, KeygenSeed};

impl KeyPair {
    /// Generates an ML-DSA key pair using the operating system RBG.
    ///
    /// This is the external FIPS 204 `ML-DSA.KeyGen()` path: it samples a fresh
    /// 32-byte seed `ξ` and then delegates to [`Self::generate_from_seed`].
    pub fn generate(parameter_set: ParameterSet) -> DilithiumResult<Self> {
        Self::generate_from_seed(parameter_set, random_bytes::<KEYGEN_SEED_BYTES>()?)
    }

    /// Generates an ML-DSA key pair from the FIPS 204 seed `ξ`.
    ///
    /// This is `ML-DSA.KeyGen_internal(ξ)` from Algorithm 6. It is deterministic
    /// and is intended for KATs, tests, and future RFC 9881 seed-only
    /// private-key import. Normal applications should use [`Self::generate`].
    ///
    /// The seed is first expanded into `ρ`, `ρ′`, and `K`. `ρ`
    /// deterministically reconstructs the public NTT-domain matrix `Â`; `ρ′`
    /// samples the short secret vectors `s₁` and `s₂`; `K` is stored in the
    /// private key for later signing mask derivation.
    ///
    /// The core relation computed here is `t = Âs₁ + s₂`. `Power2Round` then
    /// splits `t` into `(t₁, t₀)`: `t₁` is encoded into the raw public key,
    /// while `t₀` remains in the expanded private key. Finally,
    /// `tr = H(pk, 64)` is stored in the private key so signatures are bound to
    /// the public key through `μ = H(tr || M′, 64)`.
    pub fn generate_from_seed(
        parameter_set: ParameterSet,
        seed: impl Into<KeygenSeed>,
    ) -> DilithiumResult<Self> {
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

        Self::new(
            public_key,
            PrivateKey::from_raw(parameter_set, private_key_bytes)?,
        )
    }
}

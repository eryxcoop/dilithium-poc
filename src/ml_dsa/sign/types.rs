//! Typed intermediate values used by FIPS 204 signing.

use crate::encoding::w1_encode;
use crate::error::DilithiumResult;
use crate::ml_dsa::types::SigningReport;
use crate::params::ParameterSet;
use crate::poly::{NttMatrix, NttPolyVector, PolyVector};
use crate::sampling::ExpandMaskSeed;
use crate::xof::shake256;

/// Number of per-message random bytes consumed by hedged signing.
pub(crate) const SIGNING_RANDOMNESS_BYTES: usize = 32;

/// FIPS 204 `rnd` input consumed by `ML-DSA.Sign_internal`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SigningRandomness([u8; SIGNING_RANDOMNESS_BYTES]);

impl SigningRandomness {
    /// Builds signing randomness from its fixed-size byte representation.
    pub(crate) const fn new(bytes: [u8; SIGNING_RANDOMNESS_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size byte representation.
    pub(crate) const fn bytes(self) -> [u8; SIGNING_RANDOMNESS_BYTES] {
        self.0
    }

    /// Borrows the fixed-size byte representation.
    pub(crate) const fn as_bytes(&self) -> &[u8; SIGNING_RANDOMNESS_BYTES] {
        &self.0
    }

    /// Returns the deterministic FIPS 204 test value `rnd = {0}32`.
    #[cfg(any(test, feature = "instrumentation"))]
    pub(crate) const fn zero() -> Self {
        Self([0u8; SIGNING_RANDOMNESS_BYTES])
    }

    /// Computes the typed mask seed `ρ″ = H(K || rnd || μ, 64)`.
    ///
    /// The returned [`ExpandMaskSeed`] is the only valid consumer of this
    /// 64-byte signing derivation inside `Sign_internal`.
    pub(crate) fn expand_mask_seed(
        &self,
        secret_key_seed: &[u8; 32],
        mu: &MessageRepresentative,
    ) -> ExpandMaskSeed {
        let mut input = Vec::with_capacity(
            secret_key_seed.len() + SIGNING_RANDOMNESS_BYTES + mu.as_bytes().len(),
        );
        input.extend_from_slice(secret_key_seed);
        input.extend_from_slice(self.as_bytes());
        input.extend_from_slice(mu.as_bytes());

        let digest = shake256(&input, 64);
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&digest);
        ExpandMaskSeed::new(seed)
    }
}

impl From<[u8; SIGNING_RANDOMNESS_BYTES]> for SigningRandomness {
    fn from(bytes: [u8; SIGNING_RANDOMNESS_BYTES]) -> Self {
        Self::new(bytes)
    }
}

impl From<SigningRandomness> for [u8; SIGNING_RANDOMNESS_BYTES] {
    fn from(randomness: SigningRandomness) -> Self {
        randomness.bytes()
    }
}

/// FIPS 204 message representative `μ = H(tr || M′, 64)`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct MessageRepresentative([u8; 64]);

impl MessageRepresentative {
    /// Computes `μ = H(tr || M′, 64)`.
    ///
    /// `tr` is the public-key hash stored in the expanded private key, and `M′`
    /// is the external message after pure ML-DSA context formatting. Including
    /// `tr` binds signatures to the public key as well as to the formatted
    /// message.
    pub(crate) fn derive(tr: &[u8; 64], formatted_message: &[u8]) -> Self {
        let mut input = Vec::with_capacity(tr.len() + formatted_message.len());
        input.extend_from_slice(tr);
        input.extend_from_slice(formatted_message);

        let digest = shake256(&input, 64);
        let mut mu = [0u8; 64];
        mu.copy_from_slice(&digest);
        Self(mu)
    }

    /// Borrows the fixed-size byte representation.
    pub(crate) const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// FIPS 204 challenge seed `c̃ = H(μ || w1Encode(w₁), λ/4)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChallengeSeed(Vec<u8>);

impl ChallengeSeed {
    /// Computes `c̃ = H(μ || w1Encode(w₁), λ/4)`.
    ///
    /// Signing expands this seed with `SampleInBall` to obtain the sparse
    /// challenge polynomial `c`. Verification recomputes the same seed from
    /// reconstructed high bits and compares it byte-for-byte with the
    /// signature's `c̃`.
    pub(crate) fn derive(
        mu: &MessageRepresentative,
        w1: &PolyVector,
        parameter_set: ParameterSet,
    ) -> DilithiumResult<Self> {
        let encoded_w1 = w1_encode(w1, parameter_set)?;
        let mut input = Vec::with_capacity(mu.as_bytes().len() + encoded_w1.len());
        input.extend_from_slice(mu.as_bytes());
        input.extend_from_slice(&encoded_w1);
        Ok(Self(shake256(&input, parameter_set.challenge_bytes())))
    }

    /// Borrows the variable-size challenge seed bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Prepared state consumed by the signing rejection loop.
pub(super) struct SigningLoopState<'a> {
    /// ML-DSA parameter set for dimensions and bounds.
    pub(super) parameter_set: ParameterSet,
    /// Public matrix `Â`.
    pub(super) a_hat: &'a NttMatrix,
    /// Secret vector `s₁` in the NTT domain.
    pub(super) s1_hat: &'a NttPolyVector,
    /// Secret vector `s₂` in the NTT domain.
    pub(super) s2_hat: &'a NttPolyVector,
    /// Low public-key bits `t₀` in the NTT domain.
    pub(super) t0_hat: &'a NttPolyVector,
    /// Message representative `μ = H(tr || M′, 64)`.
    pub(super) mu: &'a MessageRepresentative,
    /// Signing mask seed `ρ″ = H(K || rnd || μ, 64)`.
    pub(super) mask_seed: ExpandMaskSeed,
    /// Aggregate signing report accumulated across rejected attempts.
    pub(super) report: SigningReport,
}

impl<'a> SigningLoopState<'a> {
    /// Builds the prepared state for the `ML-DSA.Sign_internal` rejection loop.
    pub(super) fn new(
        parameter_set: ParameterSet,
        a_hat: &'a NttMatrix,
        s1_hat: &'a NttPolyVector,
        s2_hat: &'a NttPolyVector,
        t0_hat: &'a NttPolyVector,
        mu: &'a MessageRepresentative,
        mask_seed: ExpandMaskSeed,
    ) -> Self {
        Self {
            parameter_set,
            a_hat,
            s1_hat,
            s2_hat,
            t0_hat,
            mu,
            mask_seed,
            report: SigningReport::default(),
        }
    }
}

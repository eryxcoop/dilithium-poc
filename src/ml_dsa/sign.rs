//! FIPS 204 ML-DSA signing.
//!
//! This module implements the external pure `ML-DSA.Sign` path. The public
//! [`sign`] API is hedged: it samples fresh 32-byte per-message randomness and
//! feeds it into the internal signing seed derivation. Deterministic entry
//! points exist only for KATs, ACVP vectors, instrumentation, and benchmarks.
//!
//! Signing starts by decoding the expanded private key:
//!
//! ```text
//! sk = skEncode(ρ, K, tr, s₁, s₂, t₀)
//! ```
//!
//! The byte-aligned external message and context are formatted as `M′` by
//! [`super::context::format_message`]. The internal representatives are then:
//!
//! ```text
//! μ  = H(tr || M′, 64)
//! ρ″ = H(K || rnd || μ, 64)
//! Â = ExpandA(ρ)
//! ```
//!
//! The rejection loop for counter `κ` is:
//!
//! ```text
//! y  = ExpandMask(ρ″, κ)
//! w  = Ây
//! w₁ = HighBits(w)
//!
//! c̃ = H(μ || w1Encode(w₁), λ/4)
//! c  = SampleInBall(c̃)
//!
//! z  = y + c·s₁
//! r₀ = LowBits(w - c·s₂)
//!
//! reject if ||z||∞  ≥ γ₁ - β
//! reject if ||r₀||∞ ≥ γ₂ - β
//!
//! reject if ||c·t₀||∞ ≥ γ₂
//! h = MakeHint(-c·t₀, w - c·s₂ + c·t₀)
//! reject if #ones(h) > ω
//!
//! sig = sigEncode(c̃, z, h)
//! ```
//!
//! Rejected attempts advance `κ` by `l`, which gives the next `ExpandMask`
//! call a distinct XOF domain. Instrumented signing records only aggregate
//! counters and sampling reports; it does not expose rejected intermediates.

use crate::encoding::{sig_encode, sk_decode, w1_encode};
use crate::error::{DilithiumError, DilithiumResult};
use crate::hints::HintsVector;
use crate::params::ParameterSet;
use crate::poly::PolyVector;
use crate::sampling::{
    ExpandASeed, ExpandMaskSeed, SamplingLimits, expand_a, expand_mask_with_limits,
    sample_in_ball_with_limits,
};
use crate::xof::shake256;

use super::context::format_message;
use super::random::random_bytes;
use super::types::{PrivateKey, Signature, SignatureWithReport, SigningReport};

/// Number of per-message random bytes consumed by hedged signing.
pub const SIGNING_RANDOMNESS_BYTES: usize = 32;

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

/// Generates a hedged ML-DSA signature using fresh operating-system randomness.
///
/// The `context` argument is the FIPS 204 pure ML-DSA context string. It is
/// prepended to the message with a domain separator and length byte before the
/// internal message representative is hashed, so it cryptographically binds the
/// signature to that context. Pass `b""` for the default context, including
/// RFC 9881 PKIX uses.
pub fn sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<Signature> {
    Ok(sign_with_report_internal(
        private_key,
        message,
        context,
        SigningRandomness::from(random_bytes::<SIGNING_RANDOMNESS_BYTES>()?),
    )?
    .into_signature())
}

/// Generates an ML-DSA signature using caller-supplied `rnd` for KAT/ACVP tests.
///
/// The `context` argument has the same domain-separation meaning as in
/// [`sign`].
///
/// This is intentionally crate-private and compiled only for tests. The public
/// API keeps hedged signing as the default and exposes only the deterministic
/// all-zero variant for tests/instrumentation.
#[cfg(test)]
pub(crate) fn sign_with_randomness_for_test(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_BYTES],
) -> DilithiumResult<Signature> {
    Ok(sign_with_report_internal(
        private_key,
        message,
        context,
        SigningRandomness::from(randomness),
    )?
    .into_signature())
}

/// Generates a hedged ML-DSA signature and returns aggregate instrumentation.
///
/// The `context` argument has the same domain-separation meaning as in
/// [`sign`].
#[cfg(feature = "instrumentation")]
pub fn sign_with_report(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<SignatureWithReport> {
    sign_with_report_internal(
        private_key,
        message,
        context,
        SigningRandomness::from(random_bytes::<SIGNING_RANDOMNESS_BYTES>()?),
    )
}

/// Generates the deterministic FIPS 204 test variant with `rnd = {0}32`.
///
/// The `context` argument has the same domain-separation meaning as in
/// [`sign`].
///
/// This function is exposed only for crate tests or the `instrumentation`
/// feature. Normal signing should use [`sign`], which follows the hedged
/// external algorithm.
#[cfg(any(test, feature = "instrumentation"))]
pub fn sign_deterministic_for_test(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<Signature> {
    Ok(sign_deterministic_for_test_with_report(private_key, message, context)?.into_signature())
}

/// Deterministic signing with aggregate rejection-loop instrumentation.
///
/// The `context` argument has the same domain-separation meaning as in
/// [`sign`].
#[cfg(any(test, feature = "instrumentation"))]
pub fn sign_deterministic_for_test_with_report(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<SignatureWithReport> {
    sign_with_report_internal(private_key, message, context, SigningRandomness::zero())
}

/// Runs the shared `ML-DSA.Sign_internal` implementation and aggregate reporting.
///
/// The caller supplies the 32-byte `rnd` input so the same implementation can
/// serve hedged signing, randomized ACVP/KAT signing, and deterministic
/// `rnd = {0}32` test signing. The returned report intentionally contains only
/// aggregate rejection and sampling counters.
fn sign_with_report_internal(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    randomness: SigningRandomness,
) -> DilithiumResult<SignatureWithReport> {
    let parameter_set = private_key.parameter_set();
    let private_parts = sk_decode(private_key.as_bytes(), parameter_set)?;
    let formatted_message = format_message(message, context)?;

    let s1_hat = private_parts.s1.ntt()?;
    let s2_hat = private_parts.s2.ntt()?;
    let t0_hat = private_parts.t0.ntt()?;
    let a_hat = expand_a(ExpandASeed::new(private_parts.rho), parameter_set)?;
    let mu = MessageRepresentative::derive(&private_parts.tr, &formatted_message);
    let mask_seed = randomness.expand_mask_seed(&private_parts.secret_key_seed, &mu);

    let mut report = SigningReport::default();
    let mut kappa = 0u16;

    loop {
        report.record_attempt();

        let sampled_y =
            expand_mask_with_limits(mask_seed, kappa, parameter_set, SamplingLimits::default())?;
        let (y, y_report) = sampled_y.into_parts();
        report.absorb_sampling(y_report);

        let w = a_hat.multiply_vector(&y, parameter_set)?;
        let w1 = w.high_bits(parameter_set)?;
        let c_tilde = ChallengeSeed::derive(&mu, &w1, parameter_set)?;
        let sampled_c = sample_in_ball_with_limits(
            c_tilde.as_bytes(),
            parameter_set,
            SamplingLimits::default(),
        )?;
        let (c, c_report) = sampled_c.into_parts();
        report.absorb_sampling(c_report);

        let c_hat = c.ntt();
        let c_s1 = c_hat.multiply_ntt_vector(&s1_hat, parameter_set.core.l)?;
        let c_s2 = c_hat.multiply_ntt_vector(&s2_hat, parameter_set.core.k)?;
        let z = y.checked_add(&c_s1)?;
        let w_minus_c_s2 = w.checked_sub(&c_s2)?;
        let r0 = w_minus_c_s2.low_bits(parameter_set)?;

        if z.infinity_norm_at_least(parameter_set.core.gamma1 - parameter_set.core.beta)
            || r0.infinity_norm_at_least(parameter_set.core.gamma2 - parameter_set.core.beta)
        {
            report.record_z_or_r0_rejection();
            kappa = next_mask_counter(kappa, parameter_set.core.l)?;
            continue;
        }

        let c_t0 = c_hat.multiply_ntt_vector(&t0_hat, parameter_set.core.k)?;
        if c_t0.infinity_norm_at_least(parameter_set.core.gamma2) {
            report.record_ct0_or_hint_rejection();
            kappa = next_mask_counter(kappa, parameter_set.core.l)?;
            continue;
        }

        let hint_target = w_minus_c_s2.checked_add(&c_t0)?;
        let hints = match HintsVector::make(parameter_set, &c_t0.neg(), &hint_target) {
            Ok(hints) => hints,
            Err(DilithiumError::ValueOutOfRange {
                item: "hint weight",
                ..
            }) => {
                report.record_ct0_or_hint_rejection();
                kappa = next_mask_counter(kappa, parameter_set.core.l)?;
                continue;
            }
            Err(error) => return Err(error),
        };

        let signature_bytes = sig_encode(c_tilde.as_bytes(), &z, &hints, parameter_set)?;
        let signature = Signature::from_raw(parameter_set, signature_bytes)?;
        return Ok(SignatureWithReport::new(signature, report));
    }
}

/// Advances the signing rejection-loop counter by the vector dimension `l`.
///
/// Each rejected attempt uses a fresh `κ` value for `ExpandMask(ρ″, κ)`. The
/// checked addition keeps overflow as an explicit error instead of wrapping
/// silently.
fn next_mask_counter(current: u16, increment: usize) -> DilithiumResult<u16> {
    current
        .checked_add(increment as u16)
        .ok_or(DilithiumError::ValueOutOfRange {
            item: "signing mask counter",
            min: 0,
            max: u16::MAX as i64,
            actual: current as i64 + increment as i64,
        })
}

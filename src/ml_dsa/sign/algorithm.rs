//! External and internal ML-DSA signing entry points.

use crate::encoding::{sig_encode, sk_decode};
use crate::error::{DilithiumError, DilithiumResult};
use crate::hints::HintsVector;
use crate::sampling::{
    ExpandASeed, SamplingLimits, expand_a, expand_mask_with_limits, sample_in_ball_with_limits,
};

use super::super::context::format_message;
use super::super::random::random_bytes;
use super::super::types::{PrivateKey, Signature, SignatureWithReport};
use super::types::{
    ChallengeSeed, MessageRepresentative, SIGNING_RANDOMNESS_BYTES, SigningLoopState,
    SigningRandomness,
};

impl PrivateKey {
    /// Generates a hedged ML-DSA signature using fresh operating-system randomness.
    ///
    /// This is the external FIPS 204 `ML-DSA.Sign()` path for pure ML-DSA. The
    /// `context` argument is prepended to the message with a domain separator
    /// and length byte before the internal message representative is hashed, so
    /// it cryptographically binds the signature to that context. Pass `b""` for
    /// the default context, including RFC 9881 PKIX uses.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> DilithiumResult<Signature> {
        Ok(self
            .sign_with_report_internal(
                message,
                context,
                SigningRandomness::from(random_bytes::<SIGNING_RANDOMNESS_BYTES>()?),
            )?
            .into_signature())
    }

    /// Generates an ML-DSA signature using caller-supplied `rnd` for KAT/ACVP tests.
    ///
    /// The `context` argument has the same domain-separation meaning as in
    /// [`PrivateKey::sign`].
    ///
    /// This is intentionally crate-private and compiled only for tests. The
    /// public API keeps hedged signing as the default and exposes only the
    /// deterministic all-zero variant for tests/instrumentation.
    #[cfg(test)]
    pub(crate) fn sign_with_randomness_for_test(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_BYTES],
    ) -> DilithiumResult<Signature> {
        Ok(self
            .sign_with_report_internal(message, context, SigningRandomness::from(randomness))?
            .into_signature())
    }

    /// Generates a hedged ML-DSA signature and returns aggregate instrumentation.
    ///
    /// The `context` argument has the same domain-separation meaning as in
    /// [`PrivateKey::sign`].
    #[cfg(feature = "instrumentation")]
    pub fn sign_with_report(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> DilithiumResult<SignatureWithReport> {
        self.sign_with_report_internal(
            message,
            context,
            SigningRandomness::from(random_bytes::<SIGNING_RANDOMNESS_BYTES>()?),
        )
    }

    /// Generates the deterministic FIPS 204 test variant with `rnd = {0}32`.
    ///
    /// The `context` argument has the same domain-separation meaning as in
    /// [`PrivateKey::sign`].
    ///
    /// This method is exposed only for crate tests or the `instrumentation`
    /// feature. Normal signing should use [`PrivateKey::sign`], which follows
    /// the hedged external algorithm.
    #[cfg(any(test, feature = "instrumentation"))]
    pub fn sign_deterministic_for_test(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> DilithiumResult<Signature> {
        Ok(self
            .sign_deterministic_for_test_with_report(message, context)?
            .into_signature())
    }

    /// Deterministic signing with aggregate rejection-loop instrumentation.
    ///
    /// The `context` argument has the same domain-separation meaning as in
    /// [`PrivateKey::sign`].
    #[cfg(any(test, feature = "instrumentation"))]
    pub fn sign_deterministic_for_test_with_report(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> DilithiumResult<SignatureWithReport> {
        self.sign_with_report_internal(message, context, SigningRandomness::zero())
    }

    /// Runs the shared `ML-DSA.Sign_internal` implementation and aggregate reporting.
    ///
    /// The caller supplies the 32-byte `rnd` input so the same implementation
    /// can serve hedged signing, randomized ACVP/KAT signing, and deterministic
    /// `rnd = {0}32` test signing. The returned report intentionally contains
    /// only aggregate rejection and sampling counters.
    fn sign_with_report_internal(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: SigningRandomness,
    ) -> DilithiumResult<SignatureWithReport> {
        let parameter_set = self.parameter_set();
        let private_parts = sk_decode(self.as_bytes(), parameter_set)?;
        let formatted_message = format_message(message, context)?;

        let s1_hat = private_parts.s1.ntt()?;
        let s2_hat = private_parts.s2.ntt()?;
        let t0_hat = private_parts.t0.ntt()?;
        let a_hat = expand_a(ExpandASeed::new(private_parts.rho), parameter_set)?;
        let mu = MessageRepresentative::derive(&private_parts.tr, &formatted_message);
        let mask_seed = randomness.expand_mask_seed(&private_parts.secret_key_seed, &mu);

        SigningLoopState::new(
            parameter_set,
            &a_hat,
            &s1_hat,
            &s2_hat,
            &t0_hat,
            &mu,
            mask_seed,
        )
        .run()
    }
}

impl SigningLoopState<'_> {
    /// Runs the FIPS 204 signing rejection loop for prepared private-key state.
    ///
    /// The state has already decoded the private key, computed `μ`, expanded
    /// `Â`, moved secret vectors to the NTT domain, and derived `ρ″`. This
    /// helper owns the repeated `ExpandMask`, challenge, bound checks,
    /// `MakeHint`, and final `sigEncode` step.
    fn run(mut self) -> DilithiumResult<SignatureWithReport> {
        let mut kappa = SigningMaskCounter::default();

        loop {
            self.report.record_attempt();

            let sampled_y = expand_mask_with_limits(
                self.mask_seed,
                kappa.value(),
                self.parameter_set,
                SamplingLimits::default(),
            )?;
            let (y, y_report) = sampled_y.into_parts();
            self.report.absorb_sampling(y_report);

            let w = self.a_hat.multiply_vector(&y, self.parameter_set)?;
            let w1 = w.high_bits(self.parameter_set)?;
            let c_tilde = ChallengeSeed::derive(self.mu, &w1, self.parameter_set)?;
            let sampled_c = sample_in_ball_with_limits(
                c_tilde.as_bytes(),
                self.parameter_set,
                SamplingLimits::default(),
            )?;
            let (c, c_report) = sampled_c.into_parts();
            self.report.absorb_sampling(c_report);

            let c_hat = c.ntt();
            let c_s1 = c_hat.multiply_ntt_vector(self.s1_hat, self.parameter_set.core.l)?;
            let c_s2 = c_hat.multiply_ntt_vector(self.s2_hat, self.parameter_set.core.k)?;
            let z = y.checked_add(&c_s1)?;
            let w_minus_c_s2 = w.checked_sub(&c_s2)?;
            let r0 = w_minus_c_s2.low_bits(self.parameter_set)?;

            if z.infinity_norm_at_least(
                self.parameter_set.core.gamma1 - self.parameter_set.core.beta,
            ) || r0.infinity_norm_at_least(
                self.parameter_set.core.gamma2 - self.parameter_set.core.beta,
            ) {
                self.report.record_z_or_r0_rejection();
                kappa.advance_by(self.parameter_set.core.l)?;
                continue;
            }

            let c_t0 = c_hat.multiply_ntt_vector(self.t0_hat, self.parameter_set.core.k)?;
            if c_t0.infinity_norm_at_least(self.parameter_set.core.gamma2) {
                self.report.record_ct0_or_hint_rejection();
                kappa.advance_by(self.parameter_set.core.l)?;
                continue;
            }

            let hint_target = w_minus_c_s2.checked_add(&c_t0)?;
            let hints = match HintsVector::make(self.parameter_set, &c_t0.neg(), &hint_target) {
                Ok(hints) => hints,
                Err(DilithiumError::ValueOutOfRange {
                    item: "hint weight",
                    ..
                }) => {
                    self.report.record_ct0_or_hint_rejection();
                    kappa.advance_by(self.parameter_set.core.l)?;
                    continue;
                }
                Err(error) => return Err(error),
            };

            let signature_bytes = sig_encode(c_tilde.as_bytes(), &z, &hints, self.parameter_set)?;
            let signature = Signature::from_raw(self.parameter_set, signature_bytes)?;
            return Ok(SignatureWithReport::new(signature, self.report));
        }
    }
}

/// Rejection-loop counter `κ` used as the `ExpandMask(ρ″, κ)` domain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SigningMaskCounter(u16);

impl SigningMaskCounter {
    /// Returns the current `κ` value.
    fn value(self) -> u16 {
        self.0
    }

    /// Advances `κ` by the vector dimension `l`.
    ///
    /// Each rejected attempt uses a fresh `κ` value for `ExpandMask(ρ″, κ)`.
    /// The checked addition keeps overflow as an explicit error instead of
    /// wrapping silently.
    fn advance_by(&mut self, increment: usize) -> DilithiumResult<()> {
        self.0 = self
            .0
            .checked_add(increment as u16)
            .ok_or(DilithiumError::ValueOutOfRange {
                item: "signing mask counter",
                min: 0,
                max: u16::MAX as i64,
                actual: self.0 as i64 + increment as i64,
            })?;
        Ok(())
    }
}

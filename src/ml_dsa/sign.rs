//! FIPS 204 ML-DSA signing.

use rand_core::{OsRng, RngCore};

use crate::encoding::{sig_encode, sk_decode, w1_encode};
use crate::error::{DilithiumError, DilithiumResult};
use crate::hints::HintsVector;
use crate::sampling::{
    ExpandASeed, ExpandMaskSeed, SamplingLimits, expand_a, expand_mask_with_limits,
    sample_in_ball_with_limits,
};
use crate::xof::shake256;

use super::algebra::{
    high_bits_vector, infinity_norm_at_least, low_bits_vector, multiply_ntt_matrix_vector,
    ntt_vector, scalar_multiply_ntt_vector,
};
use super::context::format_message;
use super::types::{PrivateKey, Signature, SignatureWithReport, SigningReport};

/// Number of per-message random bytes consumed by hedged signing.
pub const SIGNING_RANDOMNESS_BYTES: usize = 32;

/// Generates a hedged ML-DSA signature using fresh operating-system randomness.
pub fn sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<Signature> {
    Ok(
        sign_with_report_internal(private_key, message, context, signing_randomness()?)?
            .into_signature(),
    )
}

/// Generates a hedged ML-DSA signature and returns aggregate instrumentation.
#[cfg(feature = "instrumentation")]
pub fn sign_with_report(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<SignatureWithReport> {
    sign_with_report_internal(private_key, message, context, signing_randomness()?)
}

/// Generates the deterministic FIPS 204 test variant with `rnd = {0}32`.
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
#[cfg(any(test, feature = "instrumentation"))]
pub fn sign_deterministic_for_test_with_report(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
) -> DilithiumResult<SignatureWithReport> {
    sign_with_report_internal(
        private_key,
        message,
        context,
        [0u8; SIGNING_RANDOMNESS_BYTES],
    )
}

fn sign_with_report_internal(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_BYTES],
) -> DilithiumResult<SignatureWithReport> {
    let parameter_set = private_key.parameter_set();
    let private_parts = sk_decode(private_key.as_bytes(), parameter_set)?;
    let formatted_message = format_message(message, context)?;

    let s1_hat = ntt_vector(&private_parts.s1);
    let s2_hat = ntt_vector(&private_parts.s2);
    let t0_hat = ntt_vector(&private_parts.t0);
    let a_hat = expand_a(ExpandASeed::new(private_parts.rho), parameter_set)?;
    let mu = message_representative(&private_parts.tr, &formatted_message);
    let rho_second = signing_mask_seed(&private_parts.secret_key_seed, &randomness, &mu);

    let mut report = SigningReport::default();
    let mut kappa = 0u16;

    loop {
        report.record_attempt();

        let sampled_y = expand_mask_with_limits(
            ExpandMaskSeed::new(rho_second),
            kappa,
            parameter_set,
            SamplingLimits::default(),
        )?;
        let (y, y_report) = sampled_y.into_parts();
        report.absorb_sampling(y_report);

        let w = multiply_ntt_matrix_vector(&a_hat, &y, parameter_set)?;
        let w1 = high_bits_vector(&w, parameter_set)?;
        let c_tilde = commitment_hash(&mu, &w1, parameter_set)?;
        let sampled_c =
            sample_in_ball_with_limits(&c_tilde, parameter_set, SamplingLimits::default())?;
        let (c, c_report) = sampled_c.into_parts();
        report.absorb_sampling(c_report);

        let c_hat = c.ntt();
        let c_s1 = scalar_multiply_ntt_vector(&c_hat, &s1_hat, parameter_set.core.l)?;
        let c_s2 = scalar_multiply_ntt_vector(&c_hat, &s2_hat, parameter_set.core.k)?;
        let z = y.checked_add(&c_s1)?;
        let w_minus_c_s2 = w.checked_sub(&c_s2)?;
        let r0 = low_bits_vector(&w_minus_c_s2, parameter_set)?;

        if infinity_norm_at_least(&z, parameter_set.core.gamma1 - parameter_set.core.beta)
            || infinity_norm_at_least(&r0, parameter_set.core.gamma2 - parameter_set.core.beta)
        {
            report.record_z_or_r0_rejection();
            kappa = next_mask_counter(kappa, parameter_set.core.l)?;
            continue;
        }

        let c_t0 = scalar_multiply_ntt_vector(&c_hat, &t0_hat, parameter_set.core.k)?;
        if infinity_norm_at_least(&c_t0, parameter_set.core.gamma2) {
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

        let signature_bytes = sig_encode(&c_tilde, &z, &hints, parameter_set)?;
        let signature = Signature::from_raw(parameter_set, signature_bytes)?;
        return Ok(SignatureWithReport::new(signature, report));
    }
}

pub(crate) fn message_representative(tr: &[u8; 64], formatted_message: &[u8]) -> [u8; 64] {
    let mut input = Vec::with_capacity(tr.len() + formatted_message.len());
    input.extend_from_slice(tr);
    input.extend_from_slice(formatted_message);

    let digest = shake256(&input, 64);
    let mut mu = [0u8; 64];
    mu.copy_from_slice(&digest);
    mu
}

pub(crate) fn commitment_hash(
    mu: &[u8; 64],
    w1: &crate::poly::PolyVector,
    parameter_set: crate::params::ParameterSet,
) -> DilithiumResult<Vec<u8>> {
    let encoded_w1 = w1_encode(w1, parameter_set)?;
    let mut input = Vec::with_capacity(mu.len() + encoded_w1.len());
    input.extend_from_slice(mu);
    input.extend_from_slice(&encoded_w1);
    Ok(shake256(&input, parameter_set.challenge_bytes()))
}

fn signing_mask_seed(
    secret_key_seed: &[u8; 32],
    randomness: &[u8; SIGNING_RANDOMNESS_BYTES],
    mu: &[u8; 64],
) -> [u8; 64] {
    let mut input = Vec::with_capacity(secret_key_seed.len() + randomness.len() + mu.len());
    input.extend_from_slice(secret_key_seed);
    input.extend_from_slice(randomness);
    input.extend_from_slice(mu);

    let digest = shake256(&input, 64);
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&digest);
    seed
}

fn signing_randomness() -> DilithiumResult<[u8; SIGNING_RANDOMNESS_BYTES]> {
    let mut randomness = [0u8; SIGNING_RANDOMNESS_BYTES];
    OsRng
        .try_fill_bytes(&mut randomness)
        .map_err(|_| DilithiumError::Unsupported("random bit generation failed"))?;
    Ok(randomness)
}

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

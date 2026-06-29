//! # Patterned masks
//!
//! A signer can pass every structural check and still leave fingerprints in
//! the transcript.
//!
//! Here the mask sampler is not uniform. Coefficient `i` tends to drift by a
//! small, repeatable amount, so the response
//!
//! ```text
//! zᵢ = yᵢ + cᵢ·sᵢ
//! ```
//!
//! has a bias hiding under the noise. You get many sampled masks first, then
//! aggregated signing observations grouped by the event `cᵢ = 1`.
//!
//! Build the two pieces an attacker would build:
//!
//! 1. estimate the per-coefficient mask bias `E[yᵢ]`;
//! 2. use those means to estimate the secret coefficients `sᵢ`.
//!
//! **Win condition:** recover the toy secret vector closely enough that every
//! coefficient rounds back into `[-η, η]`.

/// Estimates one bias value per coefficient from sampled masks.
pub fn estimate_mask_bias_means(mask_samples: &[Vec<i64>], coefficient_count: usize) -> Vec<f64> {
    let _ = (mask_samples, coefficient_count);
    todo!("estimate the sampler bias")
}

/// Estimates toy `s₁` coefficients from aggregated signature observations.
pub fn estimate_secret_from_biased_masks(
    sums_when_challenge_one: &[i64],
    counts_when_challenge_one: &[usize],
    bias_means: &[f64],
    eta: i64,
) -> Vec<i64> {
    let _ = (
        sums_when_challenge_one,
        counts_when_challenge_one,
        bias_means,
        eta,
    );
    todo!("estimate the toy secret")
}

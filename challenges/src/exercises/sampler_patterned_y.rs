//! Exercise for `sampler_patterned_y`.

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

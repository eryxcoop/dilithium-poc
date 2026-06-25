//! Exercise for `sampler_patterned_y`.

/// Estimates toy `s₁` coefficients from a biased `y` sampler.
///
/// Inputs are aggregated over signatures and only include positions where
/// `cᵢ = 1`. For each coefficient index:
///
/// ```text
/// E[zᵢ | cᵢ = 1] ≈ E[yᵢ] + s₁ᵢ
/// ```
///
/// Complete this by averaging `zᵢ`, subtracting the known `y` bias mean,
/// rounding to the nearest integer, and clamping to `[-η, η]`.
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
    todo!("estimate s₁ from conditional means with η = 4")
}

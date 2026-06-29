//! Exercise for `eta_unbounded_secret`.

/// Estimates toy `s₁` coefficients when the secret is wider than the nominal
/// `|eta|` bound and observations are grouped by `cᵢ = 1` and `cᵢ = -1`.
pub fn estimate_secret_from_unbounded_eta(
    sums_when_challenge_one: &[i64],
    counts_when_challenge_one: &[usize],
    sums_when_challenge_minus_one: &[i64],
    counts_when_challenge_minus_one: &[usize],
) -> Vec<i64> {
    let _ = (
        sums_when_challenge_one,
        counts_when_challenge_one,
        sums_when_challenge_minus_one,
        counts_when_challenge_minus_one,
    );
    todo!("estimate the wide secret from conditional means")
}

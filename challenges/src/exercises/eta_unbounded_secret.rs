//! # Wide secrets
//!
//! The verifier still sees valid-looking signatures. The signer, however, was
//! built with secrets that are wider than the advertised `|η|` bound.
//!
//! That changes the statistics. When the challenge coefficient is positive,
//! the response leans one way:
//!
//! ```text
//! E[zᵢ | cᵢ =  1] ≈ E[yᵢ] + sᵢ
//! ```
//!
//! When it is negative, it leans the other:
//!
//! ```text
//! E[zᵢ | cᵢ = -1] ≈ E[yᵢ] - sᵢ
//! ```
//!
//! You do not get individual signatures here. You get the attacker-friendly
//! aggregates: sums and counts for both signs of the challenge. Extract `sᵢ`
//! from the split means.
//!
//! **Win condition:** recover the wide toy secret coefficients, even when they
//! would not fit inside the nominal ML-DSA `[-η, η]` promise.

/// Estimates toy `s₁` coefficients when the secret is wider than the nominal
/// `|η|` bound and observations are grouped by `cᵢ = 1` and `cᵢ = -1`.
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

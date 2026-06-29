//! # High Bits, Low Lies
//!
//! `γ₂` is the width of the rounding window. It decides which part of a
//! coefficient is a stable high bit and which part is low noise.
//!
//! During signing, ML-DSA checks the low part:
//!
//! ```text
//! r₀ = LowBits(w - c·s₂)
//! ```
//!
//! A correct signer keeps a margin:
//!
//! ```text
//! ∥r₀∥∞ < γ₂ - β
//! ```
//!
//! because `c·s₂` can shift a low-bit coefficient by as much as `β`.
//!
//! This toy signer forgot the margin and released signatures all the way out
//! to:
//!
//! ```text
//! ∥r₀∥∞ < γ₂
//! ```
//!
//! The useful samples live in the forbidden low-bit band:
//!
//! ```text
//! γ₂ - β ≤ |r₀,j| < γ₂
//! ```
//!
//! In this toy model, each kept coordinate has the form:
//!
//! ```text
//! r₀,j = noise_j - (c·s₂)_j
//! ```
//!
//! You get only the boundary coordinates. Each observation gives you the
//! sparse challenge `c` and the visible edge values of `r₀`; coordinates away
//! from the rounding edge are discarded as `None`.
//!
//! Build a low-bits boundary oracle recovery: score candidate secrets in
//! `[-η, η]^n` by how likely they make the observed `r₀` edge values. Remember
//! the sign flip: for a candidate `s`, the implied noise is
//! `r₀,j + (c·s)_j`.
//!
//! **Win condition:** recover the toy `s₂` from low-bit boundary observations
//! that a correct `γ₂ - β` rejection rule would never have released.

/// One accepted signature, reduced to the low-bit coordinates that touched the
/// forbidden `γ₂ - β ≤ |r₀,j| < γ₂` band.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LowBitsObservation {
    /// Sparse toy challenge coefficients `c ∈ {-1, 0, 1}ⁿ`.
    pub challenge: Vec<i64>,
    /// Boundary `r₀,j` values. `None` means the coordinate was not near a
    /// rounding edge.
    pub edge_r0: Vec<Option<i64>>,
}

/// Recovers the toy `s₂` from low-bit boundary observations produced by a
/// signer that checked `γ₂` instead of `γ₂ - β`.
pub fn recover_secret_from_lowbits_oracle(
    observations: &[LowBitsObservation],
    eta: i64,
) -> Vec<i64> {
    let _ = (observations, eta);
    todo!("recover the toy s2 from low-bit boundary observations")
}

/// Computes the toy cyclic product `left·right mod (xⁿ - 1)`.
///
/// Use this to evaluate `c·s` for a candidate `s₂`.
pub fn cyclic_convolution(left: &[i64], right: &[i64]) -> Vec<i64> {
    let degree = right.len();
    let mut product = vec![0; degree];

    for output_index in 0..degree {
        for input_index in 0..degree {
            product[output_index] +=
                left[input_index] * right[(output_index + degree - input_index) % degree];
        }
    }

    product
}

/// Computes one coefficient `(c·s)_j` without materializing the full product.
pub fn boundary_shift(challenge: &[i64], secret: &[i64], edge_index: usize) -> i64 {
    let degree = secret.len();
    challenge
        .iter()
        .enumerate()
        .filter(|&(_, &coefficient)| coefficient != 0)
        .map(|(challenge_index, &coefficient)| {
            coefficient * secret[(edge_index + degree - challenge_index) % degree]
        })
        .sum()
}

/// Counts how many centered low-bit noise values would survive the vulnerable
/// `γ₂` check for a given secret-dependent shift.
pub fn accepted_noise_count(shift: i64, gamma2: i64) -> usize {
    (-(gamma2 - 1)..=(gamma2 - 1))
        .filter(|&noise| (noise - shift).abs() < gamma2)
        .count()
}

/// Scores one observed boundary `r₀,j` under a candidate shift `(c·s)_j`.
pub fn lowbits_log_likelihood(r0: i64, shift: i64, gamma2: i64) -> f64 {
    let noise = r0 + shift;
    if !(-(gamma2 - 1)..=(gamma2 - 1)).contains(&noise) || r0.abs() >= gamma2 {
        return -1_000_000.0;
    }

    -(accepted_noise_count(shift, gamma2) as f64).ln()
}

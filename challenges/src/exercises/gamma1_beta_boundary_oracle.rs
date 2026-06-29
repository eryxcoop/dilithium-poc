//! # Signatures At The Edge
//!
//! A correct ML-DSA signer does not merely ask whether `z` fits under `γ₁`.
//! It leaves a safety margin:
//!
//! ```text
//! ∥z∥∞ < γ₁ - β
//! ```
//!
//! because
//!
//! ```text
//! z = y + c·s₁
//! ```
//!
//! and `c·s₁` can push a masked coefficient by as much as `β`.
//!
//! This toy signer forgot the margin and accepted signatures all the way out
//! to:
//!
//! ```text
//! ∥z∥∞ < γ₁
//! ```
//!
//! The interesting samples live in the forbidden band:
//!
//! ```text
//! γ₁ - β ≤ |z_j| < γ₁
//! ```
//!
//! You get only those boundary coordinates. Each observation gives you the
//! sparse challenge `c` and the visible edge values of `z`; coordinates outside
//! the band are discarded as `None`.
//!
//! Build a boundary oracle recovery: score candidate secrets in `[-η, η]^n`
//! by how likely they make the observed edge values. The center of the
//! distribution is boring. The edge is where the signer whispers.
//!
//! **Win condition:** recover the toy `s₁` from boundary observations that a
//! correct `γ₁ - β` rejection rule would never have released.

/// One accepted signature, reduced to the coordinates that touched the
/// forbidden `γ₁ - β ≤ |z_j| < γ₁` band.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryObservation {
    /// Sparse toy challenge coefficients `c ∈ {-1, 0, 1}ⁿ`.
    pub challenge: Vec<i64>,
    /// Boundary `z_j` values. `None` means the coordinate was not near an edge.
    pub edge_z: Vec<Option<i64>>,
}

/// Recovers the toy secret from boundary observations produced by a signer
/// that checked `γ₁` instead of `γ₁ - β`.
pub fn recover_secret_from_boundary_oracle(
    observations: &[BoundaryObservation],
    eta: i64,
) -> Vec<i64> {
    let _ = (observations, eta);
    todo!("recover the toy secret from boundary observations")
}

/// Computes the toy cyclic product `left·right mod (xⁿ - 1)`.
///
/// Use this to evaluate `c·s` for a candidate secret.
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

/// Counts how many centered mask values would survive the vulnerable `γ₁`
/// check for a given secret-dependent shift.
pub fn accepted_mask_count(shift: i64, gamma1: i64) -> usize {
    (-(gamma1 - 1)..=(gamma1 - 1))
        .filter(|&y| (y + shift).abs() < gamma1)
        .count()
}

/// Scores one observed boundary `z_j` under a candidate shift `(c·s)_j`.
pub fn boundary_log_likelihood(z: i64, shift: i64, gamma1: i64) -> f64 {
    let y = z - shift;
    if !(-(gamma1 - 1)..=(gamma1 - 1)).contains(&y) || z.abs() >= gamma1 {
        return -1_000_000.0;
    }

    -(accepted_mask_count(shift, gamma1) as f64).ln()
}

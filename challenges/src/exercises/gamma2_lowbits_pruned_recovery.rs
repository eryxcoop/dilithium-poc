//! # The Narrow Corridor
//!
//! The first low-bits challenge can be solved by trying every candidate in
//! `[-η, η]^n`. This one is too wide for that.
//!
//! The bug is the same:
//!
//! ```text
//! ∥r₀∥∞ < γ₂
//! ```
//!
//! instead of the safe margin:
//!
//! ```text
//! ∥r₀∥∞ < γ₂ - β
//! ```
//!
//! but now `n` is large enough that brute force is a dead end:
//!
//! ```text
//! (2η + 1)^20 = 5^20
//! ```
//!
//! Each edge coordinate still gives the same equation:
//!
//! ```text
//! r₀,j = noise_j - (c·s₂)_j
//! ```
//!
//! so the implied noise is:
//!
//! ```text
//! noise_j = r₀,j + (c·s₂)_j
//! ```
//!
//! Since the noise must lie in `[-γ₂ + 1, γ₂ - 1]`, every observed edge gives a
//! constraint:
//!
//! ```text
//! -(γ₂ - 1) - r₀,j ≤ (c·s₂)_j ≤ (γ₂ - 1) - r₀,j
//! ```
//!
//! This is the corridor. A partial candidate either can still pass through it,
//! or it cannot.
//!
//! Build a pruned recovery:
//!
//! 1. turn edge observations into sparse interval constraints;
//! 2. assign secret coefficients one by one;
//! 3. for each partial assignment, bound the unknown contribution by `±η`;
//! 4. prune branches whose possible interval no longer intersects the allowed
//!    interval;
//! 5. rank the remaining complete candidates by low-bits likelihood.
//!
//! **Win condition:** recover the toy `s₂` without enumerating all `5²⁰`
//! candidates.

/// One accepted signature, reduced to low-bit coordinates that touched the
/// forbidden `γ₂ - β ≤ |r₀,j| < γ₂` band.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrunedLowBitsObservation {
    /// Sparse toy challenge coefficients `c ∈ {-1, 0, 1}ⁿ`.
    pub challenge: Vec<i64>,
    /// Boundary `r₀,j` values. `None` means the coordinate was not near a
    /// rounding edge.
    pub edge_r0: Vec<Option<i64>>,
}

/// One sparse interval constraint on a candidate secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryConstraint {
    /// Terms `(index, sign)` describing `(c·s)_j`.
    pub terms: Vec<(usize, i64)>,
    /// Lower allowed value for `(c·s)_j`.
    pub lower: i64,
    /// Upper allowed value for `(c·s)_j`.
    pub upper: i64,
    /// Observed low-bit edge value, used later for likelihood ranking.
    pub r0: i64,
}

/// Recovers toy `s₂` using interval pruning instead of full brute force.
pub fn recover_secret_with_pruning(
    observations: &[PrunedLowBitsObservation],
    eta: i64,
    gamma2: i64,
) -> Vec<i64> {
    let _ = (observations, eta, gamma2);
    todo!("recover the toy s2 with pruned boundary constraints")
}

/// Converts low-bit edge observations into sparse interval constraints.
pub fn constraints_from_observations(
    observations: &[PrunedLowBitsObservation],
    gamma2: i64,
) -> Vec<BoundaryConstraint> {
    let _ = (observations, gamma2);
    todo!("convert low-bit edge observations into sparse interval constraints")
}

/// Returns `(partial, missing)` for a partially assigned sparse shift.
///
/// The full shift must lie inside:
///
/// ```text
/// [partial - missing, partial + missing]
/// ```
pub fn partial_shift_range(
    terms: &[(usize, i64)],
    assignment: &[Option<i64>],
    eta: i64,
) -> (i64, i64) {
    let mut partial = 0;
    let mut missing = 0;

    for &(index, sign) in terms {
        match assignment[index] {
            Some(value) => partial += sign * value,
            None => missing += eta,
        }
    }

    (partial, missing)
}

/// Returns `true` when a partial assignment can still satisfy the constraint.
pub fn constraint_remains_possible(
    constraint: &BoundaryConstraint,
    assignment: &[Option<i64>],
    eta: i64,
) -> bool {
    let (partial, missing) = partial_shift_range(&constraint.terms, assignment, eta);
    partial - missing <= constraint.upper && partial + missing >= constraint.lower
}

/// Counts how many centered low-bit noise values survive the vulnerable `γ₂`
/// check for a given shift.
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

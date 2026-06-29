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

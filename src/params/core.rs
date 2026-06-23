//! Core cryptographic parameters for ML-DSA.

/// Core cryptographic parameters for one ML-DSA parameter set.
///
/// These values drive the algebraic dimensions, rejection bounds, challenge
/// shape, and hint limits used by FIPS 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreParams {
    /// Number of rows in the public matrix `A`.
    pub k: usize,
    /// Number of columns in the public matrix `A`.
    pub l: usize,
    /// Coefficient bound for the secret vectors `s1` and `s2`.
    pub eta: u32,
    /// Number of non-zero `+/-1` coefficients in the challenge polynomial.
    pub tau: u32,
    /// Collision-security parameter for the commitment hash `c_tilde`.
    pub lambda: u32,
    /// Coefficient range parameter for the masking vector `y`.
    pub gamma1: u32,
    /// Low-order rounding range used by decomposition and hints.
    pub gamma2: u32,
    /// Bound `tau * eta` used in signing rejection checks.
    pub beta: u32,
    /// Maximum number of one bits allowed in the hint vector `h`.
    pub omega: u32,
}

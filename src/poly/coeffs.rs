//! Fixed-size coefficient storage for one polynomial.

use crate::coefficient::Coefficient;
use crate::params::N;

/// Coefficients for one polynomial in the ring `R_q = Z_q[X] / (X^256 + 1)`.
pub type Coefficients = [Coefficient; N];

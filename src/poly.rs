//! Core algebraic domain types for ML-DSA.
//!
//! These are intentionally lightweight M1 data shapes. Arithmetic operations
//! will be introduced in later milestones.

use crate::error::{Error, Result};
use crate::params::{N, ParameterSet};

/// Coefficients for a polynomial in the ring `R_q = Z_q[X] / (X^256 + 1)`.
pub type Coefficients = [i32; N];

/// Polynomial in the ring `R_q = Z_q[X] / (X^256 + 1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poly {
    coeffs: Coefficients,
}

/// Vector of polynomials with a fixed runtime dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVector {
    dimension: usize,
    polys: Vec<Poly>,
}

/// Matrix of polynomials with `rows x cols` runtime dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyMatrix {
    rows: usize,
    cols: usize,
    polys: Vec<Poly>,
}

impl Poly {
    /// Returns the all-zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Builds a polynomial from its coefficient array.
    pub fn from_coeffs(coeffs: Coefficients) -> Self {
        Self { coeffs }
    }

    /// Returns the coefficient array.
    pub fn coeffs(&self) -> &Coefficients {
        &self.coeffs
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl PolyVector {
    /// Returns a zero vector with the requested dimension.
    pub fn zero(dimension: usize) -> Self {
        Self {
            dimension,
            polys: vec![Poly::zero(); dimension],
        }
    }

    /// Returns a zero vector with the `l` dimension of the parameter set.
    pub fn zero_l(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.l)
    }

    /// Returns a zero vector with the `k` dimension of the parameter set.
    pub fn zero_k(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.k)
    }

    /// Builds a vector from explicit polynomials.
    pub fn from_polys(dimension: usize, polys: Vec<Poly>) -> Result<Self> {
        ensure_item_len("polynomial vector", dimension, polys.len())?;
        Ok(Self { dimension, polys })
    }

    /// Returns the vector dimension.
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }
}

impl PolyMatrix {
    /// Returns a zero matrix with the requested dimensions.
    pub fn zero(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            polys: vec![Poly::zero(); rows * cols],
        }
    }

    /// Returns a zero matrix with ML-DSA dimensions `(k, l)`.
    pub fn zero_kl(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.k, parameter_set.core.l)
    }

    /// Builds a matrix from explicit polynomials in row-major order.
    pub fn from_polys(rows: usize, cols: usize, polys: Vec<Poly>) -> Result<Self> {
        ensure_item_len("polynomial matrix", rows * cols, polys.len())?;
        Ok(Self { rows, cols, polys })
    }

    /// Returns the number of rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Returns the row-major polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }
}

fn ensure_item_len(item: &'static str, expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual,
            item,
        })
    }
}

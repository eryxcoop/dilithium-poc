//! Polynomial type for ML-DSA.

use core::array;
use core::ops::{Add, Neg, Sub};

use crate::coefficient::Coefficient;
use crate::poly::Coefficients;

/// Polynomial in the ring `R_q = Z_q[X] / (X^256 + 1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poly {
    coeffs: Coefficients,
}

impl Poly {
    /// Returns the all-zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: [Coefficient::default(); crate::params::N],
        }
    }

    /// Builds a polynomial from its coefficient array.
    pub fn from_coeffs(coeffs: Coefficients) -> Self {
        Self { coeffs }
    }

    /// Returns the coefficient array.
    pub fn coeffs(&self) -> &Coefficients {
        &self.coeffs
    }

    /// Returns one coefficient by index.
    pub fn coeff(&self, index: usize) -> Option<Coefficient> {
        self.coeffs.get(index).copied()
    }

    /// Returns an iterator over the coefficients.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Coefficient> + '_ {
        self.coeffs.iter().copied()
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add for Poly {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::from_coeffs(array::from_fn(|index| {
            self.coeffs[index] + rhs.coeffs[index]
        }))
    }
}

impl Sub for Poly {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::from_coeffs(array::from_fn(|index| {
            self.coeffs[index] - rhs.coeffs[index]
        }))
    }
}

impl Neg for Poly {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::from_coeffs(array::from_fn(|index| -self.coeffs[index]))
    }
}

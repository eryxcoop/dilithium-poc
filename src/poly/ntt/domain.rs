//! Transform-domain polynomial type.

use core::array;
use core::ops::{Add, Mul};

use crate::coefficient::Coefficient;
use crate::params::N;
use crate::poly::ntt::transform::inverse_impl;
use crate::poly::{Coefficients, Poly};

/// One element of `T_q`, the transform domain used by the ML-DSA NTT.
///
/// This is the NTT-domain counterpart of [`Poly`]. A [`Poly`] stores the usual
/// coefficient representation of an element of
/// `R_q = Z_q[X] / (X^256 + 1)`, while `NttPoly` stores the transformed
/// representation used by FIPS 204 for efficient multiplication.
///
/// The practical reason this type exists is to keep the two domains explicit:
///
/// - [`Poly`] lives in the "normal" polynomial domain.
/// - `NttPoly` lives in the transformed domain `T_q`.
/// - Multiplication in [`Poly`] is negacyclic convolution.
/// - Multiplication in `NttPoly` is pointwise coefficient multiplication.
///
/// Typical usage is:
///
/// 1. call [`Poly::ntt`] to transform a [`Poly`] into an `NttPoly`,
/// 2. multiply two `NttPoly` values pointwise,
/// 3. call [`NttPoly::inverse_ntt`] to return to [`Poly`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttPoly {
    coeffs: Coefficients,
}

impl NttPoly {
    /// Returns the all-zero transform-domain element.
    pub fn zero() -> Self {
        Self {
            coeffs: [Coefficient::default(); N],
        }
    }

    /// Builds a transform-domain element from its coefficient array.
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

    /// Returns an iterator over the transform-domain coefficients.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Coefficient> + '_ {
        self.coeffs.iter().copied()
    }

    /// Computes the inverse FIPS 204 NTT.
    ///
    /// This maps an [`NttPoly`] from the transform domain `T_q` back into the
    /// coefficient domain [`Poly`].
    pub fn inverse_ntt(&self) -> Poly {
        inverse_impl(self)
    }
}

impl Default for NttPoly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add<&NttPoly> for &NttPoly {
    type Output = NttPoly;

    fn add(self, rhs: &NttPoly) -> Self::Output {
        NttPoly::from_coeffs(array::from_fn(|index| {
            self.coeffs[index] + rhs.coeffs[index]
        }))
    }
}

impl Mul<&NttPoly> for &NttPoly {
    type Output = NttPoly;

    fn mul(self, rhs: &NttPoly) -> Self::Output {
        NttPoly::from_coeffs(array::from_fn(|index| {
            self.coeffs[index] * rhs.coeffs[index]
        }))
    }
}

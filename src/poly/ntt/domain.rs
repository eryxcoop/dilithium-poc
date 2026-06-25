//! Transform-domain polynomial type.

use core::array;
use core::ops::{Add, Mul};

use crate::coefficient::Coefficient;
use crate::error::DilithiumResult;
use crate::params::N;
use crate::poly::ntt::transform::inverse_impl;
use crate::poly::{Coefficients, NttPolyVector, Poly, PolyVector};
use crate::validation::ensure_dimension;

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

    /// Computes a dot product in the NTT domain.
    ///
    /// Matrix-vector multiplication uses this to accumulate one row of `Â`
    /// against an NTT-domain vector. The inputs must already have matching
    /// lengths; dimension checks live at the matrix/vector boundary.
    pub(crate) fn dot_product(lhs: &[Self], rhs: &[Self]) -> Self {
        let mut sum = Self::zero();
        for (lhs, rhs) in lhs.iter().zip(rhs.iter()) {
            let product = lhs * rhs;
            sum = &sum + &product;
        }
        sum
    }

    /// Multiplies this NTT-domain polynomial by every polynomial in an NTT vector.
    ///
    /// Signing and verification use this for challenge products such as `c·s₁`,
    /// `c·s₂`, `c·t₀`, and `c·t₁·2ᵈ`. Each pointwise product is converted back
    /// to coefficient representation before returning.
    pub(crate) fn multiply_ntt_vector(
        &self,
        vector_hat: &NttPolyVector,
        expected_dimension: usize,
    ) -> DilithiumResult<PolyVector> {
        ensure_dimension(
            "NTT vector dimension",
            expected_dimension,
            vector_hat.dimension(),
        )?;

        let products = vector_hat
            .iter()
            .map(|poly_hat| (self * poly_hat).inverse_ntt())
            .collect();

        PolyVector::from_polys(expected_dimension, products)
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

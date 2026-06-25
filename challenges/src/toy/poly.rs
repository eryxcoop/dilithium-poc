//! Toy negacyclic polynomials.

use super::{ToyAlgebraError, ToyParams};

/// Polynomial in the toy ring `Z_q[X] / (X^n + 1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyPoly {
    params: ToyParams,
    coeffs: Vec<i64>,
}

impl ToyPoly {
    /// Returns the zero polynomial for the given toy ring.
    pub fn zero(params: ToyParams) -> Self {
        Self {
            params,
            coeffs: vec![0; params.degree()],
        }
    }

    /// Builds a polynomial from raw coefficients reduced modulo `q`.
    pub fn from_coeffs(
        params: ToyParams,
        coeffs: impl Into<Vec<i64>>,
    ) -> Result<Self, ToyAlgebraError> {
        let coeffs = coeffs.into();
        if coeffs.len() != params.degree() {
            return Err(ToyAlgebraError::LengthMismatch {
                expected: params.degree(),
                actual: coeffs.len(),
            });
        }

        Ok(Self {
            params,
            coeffs: coeffs
                .into_iter()
                .map(|value| params.reduce(value))
                .collect(),
        })
    }

    /// Returns the toy ring parameters.
    pub fn params(&self) -> ToyParams {
        self.params
    }

    /// Returns canonical coefficients in `[0, q)`.
    pub fn coeffs(&self) -> &[i64] {
        &self.coeffs
    }

    /// Returns centered coefficients.
    pub fn centered_coeffs(&self) -> Vec<i64> {
        self.coeffs
            .iter()
            .map(|&value| self.params.centered(value))
            .collect()
    }

    /// Returns the coefficient `∞` norm using centered representatives.
    pub fn infinity_norm(&self) -> i64 {
        self.coeffs
            .iter()
            .map(|&value| self.params.centered(value).abs())
            .max()
            .unwrap_or(0)
    }

    /// Adds two toy polynomials in the same ring.
    pub fn checked_add(&self, rhs: &Self) -> Result<Self, ToyAlgebraError> {
        self.ensure_same_params(rhs)?;
        Self::from_coeffs(
            self.params,
            self.coeffs
                .iter()
                .zip(rhs.coeffs.iter())
                .map(|(&lhs, &rhs)| lhs + rhs)
                .collect::<Vec<_>>(),
        )
    }

    /// Subtracts two toy polynomials in the same ring.
    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, ToyAlgebraError> {
        self.ensure_same_params(rhs)?;
        Self::from_coeffs(
            self.params,
            self.coeffs
                .iter()
                .zip(rhs.coeffs.iter())
                .map(|(&lhs, &rhs)| lhs - rhs)
                .collect::<Vec<_>>(),
        )
    }

    /// Returns `-self`.
    pub fn neg(&self) -> Self {
        Self::from_coeffs(
            self.params,
            self.coeffs.iter().map(|&value| -value).collect::<Vec<_>>(),
        )
        .expect("negation preserves polynomial length")
    }

    /// Multiplies by a scalar modulo `q`.
    pub fn scalar_mul(&self, scalar: i64) -> Self {
        Self::from_coeffs(
            self.params,
            self.coeffs
                .iter()
                .map(|&value| value * scalar)
                .collect::<Vec<_>>(),
        )
        .expect("scalar multiplication preserves polynomial length")
    }

    /// Multiplies in `Z_q[X] / (X^n + 1)`.
    pub fn checked_mul(&self, rhs: &Self) -> Result<Self, ToyAlgebraError> {
        self.ensure_same_params(rhs)?;

        let n = self.params.degree();
        let mut coeffs = vec![0i64; n];
        for lhs_index in 0..n {
            for rhs_index in 0..n {
                let raw_index = lhs_index + rhs_index;
                let product = self.coeffs[lhs_index] * rhs.coeffs[rhs_index];
                if raw_index < n {
                    coeffs[raw_index] += product;
                } else {
                    coeffs[raw_index - n] -= product;
                }
            }
        }

        Self::from_coeffs(self.params, coeffs)
    }

    fn ensure_same_params(&self, rhs: &Self) -> Result<(), ToyAlgebraError> {
        if self.params == rhs.params {
            Ok(())
        } else {
            Err(ToyAlgebraError::ParameterMismatch)
        }
    }
}

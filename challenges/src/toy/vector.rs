//! Toy polynomial vectors.

use super::{ToyAlgebraError, ToyParams, ToyPoly};

/// Vector of toy polynomials all belonging to the same toy ring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyVector {
    params: ToyParams,
    polys: Vec<ToyPoly>,
}

impl ToyVector {
    /// Returns a zero vector with the requested dimension.
    pub fn zero(params: ToyParams, dimension: usize) -> Self {
        Self {
            params,
            polys: vec![ToyPoly::zero(params); dimension],
        }
    }

    /// Builds a vector from explicit toy polynomials.
    pub fn from_polys(params: ToyParams, polys: Vec<ToyPoly>) -> Result<Self, ToyAlgebraError> {
        for poly in &polys {
            if poly.params() != params {
                return Err(ToyAlgebraError::ParameterMismatch);
            }
        }
        Ok(Self { params, polys })
    }

    /// Returns the toy ring parameters.
    pub fn params(&self) -> ToyParams {
        self.params
    }

    /// Returns the vector dimension.
    pub fn dimension(&self) -> usize {
        self.polys.len()
    }

    /// Returns the polynomial slice.
    pub fn polys(&self) -> &[ToyPoly] {
        &self.polys
    }

    /// Returns the largest centered coefficient absolute value.
    pub fn infinity_norm(&self) -> i64 {
        self.polys
            .iter()
            .map(ToyPoly::infinity_norm)
            .max()
            .unwrap_or(0)
    }

    /// Adds two toy vectors with the same dimension and toy ring.
    pub fn checked_add(&self, rhs: &Self) -> Result<Self, ToyAlgebraError> {
        self.ensure_compatible(rhs)?;
        let polys = self
            .polys
            .iter()
            .zip(rhs.polys.iter())
            .map(|(lhs, rhs)| lhs.checked_add(rhs))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_polys(self.params, polys)
    }

    /// Subtracts two toy vectors with the same dimension and toy ring.
    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, ToyAlgebraError> {
        self.ensure_compatible(rhs)?;
        let polys = self
            .polys
            .iter()
            .zip(rhs.polys.iter())
            .map(|(lhs, rhs)| lhs.checked_sub(rhs))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_polys(self.params, polys)
    }

    fn ensure_compatible(&self, rhs: &Self) -> Result<(), ToyAlgebraError> {
        if self.params != rhs.params {
            return Err(ToyAlgebraError::ParameterMismatch);
        }
        if self.dimension() != rhs.dimension() {
            return Err(ToyAlgebraError::DimensionMismatch {
                expected: self.dimension(),
                actual: rhs.dimension(),
            });
        }
        Ok(())
    }
}

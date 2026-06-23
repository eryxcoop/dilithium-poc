//! Polynomial-vector type for ML-DSA.

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::ParameterSet;
use crate::poly::Poly;
use crate::validation::{ensure_dimension, ensure_len};

/// Vector of polynomials with a fixed runtime dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVector {
    dimension: usize,
    polys: Vec<Poly>,
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
    pub fn from_polys(dimension: usize, polys: Vec<Poly>) -> DilithiumResult<Self> {
        ensure_len("polynomial vector", dimension, polys.len())?;
        Ok(Self { dimension, polys })
    }

    /// Returns the vector dimension.
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns `true` when the vector contains no polynomials.
    pub fn is_empty(&self) -> bool {
        self.dimension == 0
    }

    /// Returns one polynomial by index.
    pub fn get(&self, index: usize) -> Option<&Poly> {
        self.polys.get(index)
    }

    /// Returns an iterator over the polynomials.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Poly> + '_ {
        self.polys.iter()
    }

    /// Returns the polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }

    /// Returns the number of one coefficients in a binary polynomial vector.
    ///
    /// This helper is useful for ML-DSA hint vectors, where every coefficient
    /// must be either `0` or `1` and the total number of ones is bounded by
    /// `omega`. It returns [`DilithiumError::ValueOutOfRange`] if any coefficient
    /// is not binary.
    pub fn binary_weight(&self) -> DilithiumResult<usize> {
        let mut weight = 0usize;

        for poly in self.iter() {
            for coefficient in poly.iter() {
                match coefficient.value() {
                    0 => {}
                    1 => weight += 1,
                    value => {
                        return Err(DilithiumError::ValueOutOfRange {
                            item: "hint coefficient",
                            min: 0,
                            max: 1,
                            actual: value as i64,
                        });
                    }
                }
            }
        }

        Ok(weight)
    }

    /// Adds two vectors coefficientwise after checking that dimensions match.
    pub fn checked_add(&self, rhs: &Self) -> DilithiumResult<Self> {
        self.ensure_same_dimension(rhs)?;
        Ok(Self {
            dimension: self.dimension,
            polys: self
                .polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(lhs, rhs)| lhs + rhs)
                .collect(),
        })
    }

    /// Subtracts two vectors coefficientwise after checking that dimensions match.
    pub fn checked_sub(&self, rhs: &Self) -> DilithiumResult<Self> {
        self.ensure_same_dimension(rhs)?;
        Ok(Self {
            dimension: self.dimension,
            polys: self
                .polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(lhs, rhs)| lhs - rhs)
                .collect(),
        })
    }

    /// Returns the coefficientwise modular negation of the vector.
    pub fn neg(&self) -> Self {
        Self {
            dimension: self.dimension,
            polys: self.polys.iter().map(|poly| -poly).collect(),
        }
    }

    fn ensure_same_dimension(&self, rhs: &Self) -> DilithiumResult<()> {
        ensure_dimension("polynomial vector dimension", self.dimension, rhs.dimension)
    }
}

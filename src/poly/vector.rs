//! Polynomial-vector type for ML-DSA.

use crate::error::{Error, Result};
use crate::params::ParameterSet;
use crate::poly::Poly;
use crate::poly::validation::ensure_item_len;

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
    pub fn from_polys(dimension: usize, polys: Vec<Poly>) -> Result<Self> {
        ensure_item_len("polynomial vector", dimension, polys.len())?;
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

    /// Adds two vectors coefficientwise after checking that dimensions match.
    pub fn checked_add(&self, rhs: &Self) -> Result<Self> {
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
    pub fn checked_sub(&self, rhs: &Self) -> Result<Self> {
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

    fn ensure_same_dimension(&self, rhs: &Self) -> Result<()> {
        if self.dimension == rhs.dimension {
            Ok(())
        } else {
            Err(Error::DimensionMismatch {
                expected: self.dimension,
                actual: rhs.dimension,
                item: "polynomial vector dimension",
            })
        }
    }
}

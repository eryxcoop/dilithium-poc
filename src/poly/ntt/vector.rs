//! Vector of transform-domain polynomials.

use crate::error::DilithiumResult;
use crate::poly::{NttPoly, PolyVector};
use crate::validation::ensure_len;

/// Vector of NTT-domain polynomials with a fixed runtime dimension.
///
/// This is the transform-domain counterpart of [`PolyVector`]. It makes the
/// domain boundary explicit in high-level ML-DSA code: ordinary [`PolyVector`]
/// values live in coefficient representation, while `NttPolyVector` values are
/// ready for pointwise multiplication in `T_q`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttPolyVector {
    dimension: usize,
    polys: Vec<NttPoly>,
}

impl NttPolyVector {
    /// Returns a zero transform-domain vector with the requested dimension.
    pub fn zero(dimension: usize) -> Self {
        Self {
            dimension,
            polys: vec![NttPoly::zero(); dimension],
        }
    }

    /// Builds a transform-domain vector from explicit polynomials.
    pub fn from_polys(dimension: usize, polys: Vec<NttPoly>) -> DilithiumResult<Self> {
        ensure_len("NTT polynomial vector", dimension, polys.len())?;
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

    /// Returns one transform-domain polynomial by index.
    pub fn get(&self, index: usize) -> Option<&NttPoly> {
        self.polys.get(index)
    }

    /// Returns an iterator over the transform-domain polynomials.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &NttPoly> + '_ {
        self.polys.iter()
    }

    /// Returns the transform-domain polynomial slice.
    pub fn polys(&self) -> &[NttPoly] {
        &self.polys
    }

    /// Applies the inverse NTT to every polynomial in the vector.
    pub fn inverse_ntt(&self) -> DilithiumResult<PolyVector> {
        PolyVector::from_polys(
            self.dimension,
            self.polys.iter().map(NttPoly::inverse_ntt).collect(),
        )
    }
}

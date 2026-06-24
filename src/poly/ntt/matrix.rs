//! Matrix of transform-domain polynomials.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::poly::NttPoly;
use crate::validation::ensure_len;

/// Matrix of transform-domain polynomials with `rows × cols` dimensions.
///
/// FIPS 204 `ExpandA(ρ)` samples the public matrix as `Â`, a `k × l`
/// matrix whose entries are already elements of the NTT domain `T_q`. This type
/// keeps that representation distinct from [`crate::poly::PolyMatrix`], which
/// stores ordinary coefficient-domain polynomials in `R_q`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttMatrix {
    rows: usize,
    cols: usize,
    polys: Vec<NttPoly>,
}

impl NttMatrix {
    /// Returns a zero matrix with the requested dimensions.
    pub fn zero(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            polys: vec![NttPoly::zero(); rows * cols],
        }
    }

    /// Returns a zero matrix with the ML-DSA public-matrix dimensions `(k, l)`.
    pub fn zero_kl(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.k, parameter_set.core.l)
    }

    /// Builds a matrix from explicit transform-domain polynomials in row-major order.
    pub fn from_polys(rows: usize, cols: usize, polys: Vec<NttPoly>) -> DilithiumResult<Self> {
        ensure_len("NTT polynomial matrix", rows * cols, polys.len())?;
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

    /// Returns the matrix shape as `(rows, cols)`.
    pub fn shape(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    /// Returns one transform-domain polynomial by `(row, col)` position.
    pub fn get(&self, row: usize, col: usize) -> Option<&NttPoly> {
        if row < self.rows && col < self.cols {
            self.polys.get(row * self.cols + col)
        } else {
            None
        }
    }

    /// Returns one full row as a contiguous slice.
    pub fn row(&self, row: usize) -> Option<&[NttPoly]> {
        if row < self.rows {
            let start = row * self.cols;
            let end = start + self.cols;
            Some(&self.polys[start..end])
        } else {
            None
        }
    }

    /// Returns an iterator over the rows of the matrix.
    pub fn rows_iter(&self) -> impl ExactSizeIterator<Item = &[NttPoly]> + '_ {
        self.polys.chunks(self.cols)
    }

    /// Returns the row-major polynomial slice.
    pub fn polys(&self) -> &[NttPoly] {
        &self.polys
    }
}

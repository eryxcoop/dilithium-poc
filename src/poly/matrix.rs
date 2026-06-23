//! Polynomial-matrix type for ML-DSA.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::poly::Poly;
use crate::poly::validation::ensure_item_len;

/// Matrix of polynomials with `rows x cols` runtime dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyMatrix {
    rows: usize,
    cols: usize,
    polys: Vec<Poly>,
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
    pub fn from_polys(rows: usize, cols: usize, polys: Vec<Poly>) -> DilithiumResult<Self> {
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

    /// Returns the matrix shape as `(rows, cols)`.
    pub fn shape(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    /// Returns `true` when the matrix has zero rows or zero columns.
    pub fn is_empty(&self) -> bool {
        self.rows == 0 || self.cols == 0
    }

    /// Returns one polynomial by `(row, col)` position.
    pub fn get(&self, row: usize, col: usize) -> Option<&Poly> {
        if row < self.rows && col < self.cols {
            self.polys.get(row * self.cols + col)
        } else {
            None
        }
    }

    /// Returns one full row as a contiguous slice.
    pub fn row(&self, row: usize) -> Option<&[Poly]> {
        if row < self.rows {
            let start = row * self.cols;
            let end = start + self.cols;
            Some(&self.polys[start..end])
        } else {
            None
        }
    }

    /// Returns an iterator over the rows of the matrix.
    pub fn rows_iter(&self) -> impl ExactSizeIterator<Item = &[Poly]> + '_ {
        self.polys.chunks(self.cols)
    }

    /// Returns the row-major polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }
}

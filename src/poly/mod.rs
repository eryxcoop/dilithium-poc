//! Core algebraic domain types for ML-DSA.
//!
//! This module contains structural representations of polynomials, vectors, and
//! matrices over `R_q`. Modular arithmetic over individual coefficients lives in
//! [`crate::coefficient`].

mod coeffs;
mod matrix;
mod polynomial;
mod validation;
mod vector;

pub use coeffs::Coefficients;
pub use matrix::PolyMatrix;
pub use polynomial::Poly;
pub use vector::PolyVector;

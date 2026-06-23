//! Number-theoretic transform primitives for ML-DSA.
//!
//! This module implements the NTT and inverse NTT used by FIPS 204. The public
//! API is intentionally small: transform a polynomial into `T_q`, invert it
//! back into `R_q`, and perform pointwise arithmetic in the transform domain.

mod domain;
mod tables;
mod transform;

pub use domain::NttPoly;

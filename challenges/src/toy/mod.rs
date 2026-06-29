//! Separate toy algebra for educational challenge parameters.
//!
//! These types intentionally do not reuse the production `Poly` and
//! `PolyVector` types from `dilithium-poc`. Toy challenges may shrink `n`,
//! change `q`, or violate ML-DSA parameter coupling; keeping those experiments
//! in their own algebra prevents them from looking FIPS-compatible.

mod hints;
mod params;
mod poly;
mod vector;

pub use hints::{bits_from_mask, first_hint_positions, hint_weight, use_hints};
pub use params::{ToyAlgebraError, ToyParams};
pub use poly::ToyPoly;
pub use vector::ToyVector;

//! POC de ML-DSA segun FIPS 204 y RFC 9881.
//!
//! El crate todavia esta en fase de scaffold. La planificacion tecnica vive en
//! `roadmap.md` y las notas normativas para colaboradores viven en `AGENTS.md`.

pub mod coefficient;
pub mod encoding;
pub mod error;
pub mod hints;
pub mod ml_dsa;
pub mod params;
#[cfg(feature = "pkix")]
pub mod pkix;
pub mod poly;
pub mod round;
pub mod sampling;
mod validation;
pub mod xof;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../conformance/mod.rs"]
mod conformance;

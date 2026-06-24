//! POC de ML-DSA segun FIPS 204 y RFC 9881.
//!
//! El crate todavia esta en fase de scaffold. La planificacion tecnica vive en
//! `roadmap.md` y las notas normativas para colaboradores viven en `AGENTS.md`.

pub mod coefficient;
pub mod encoding;
pub mod error;
pub mod hints;
pub mod params;
pub mod poly;
pub mod round;
pub mod sampling;
pub mod types;
mod validation;
pub mod verify;
pub mod xof;

#[cfg(test)]
mod tests;

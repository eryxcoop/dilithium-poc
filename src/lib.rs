//! POC de ML-DSA segun FIPS 204 y RFC 9881.
//!
//! El crate todavia esta en fase de scaffold. La planificacion tecnica vive en
//! `roadmap.md` y las notas normativas para colaboradores viven en `AGENTS.md`.

pub mod coefficient;
pub mod error;
pub mod params;
pub mod poly;
pub mod round;
pub mod types;

#[cfg(test)]
mod tests;

pub use coefficient::{CANONICAL_MAX, CANONICAL_MIN, CENTERED_MAX, CENTERED_MIN, Coefficient};
pub use error::{Error, Result};
pub use params::{
    CoreParams, D, EncodedSizes, ML_DSA_44, ML_DSA_65, ML_DSA_87, N, PARAMETER_SETS, ParameterSet,
    ParameterSetId, Q, ZETA,
};
pub use poly::{NttPoly, Poly, PolyMatrix, PolyVector};
pub use round::{Decomposed, Power2Round};
pub use types::{PrivateKey, PublicKey, Signature};

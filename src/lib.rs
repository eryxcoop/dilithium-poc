//! POC de ML-DSA segun FIPS 204 y RFC 9881.
//!
//! El crate todavia esta en fase de scaffold. La planificacion tecnica vive en
//! `roadmap.md` y las notas normativas para colaboradores viven en `AGENTS.md`.

pub mod error;
pub mod params;
pub mod types;

pub use error::{Error, Result};
pub use params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ParameterSet, ParameterSetId};
pub use types::{PrivateKey, PublicKey, Signature};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_scaffold_is_ready() {
        assert_eq!(env!("CARGO_PKG_NAME"), "dilithium-poc");
    }

    #[test]
    fn fips_parameter_sets_are_exposed() {
        assert_eq!(ML_DSA_44.public_key_bytes, 1312);
        assert_eq!(ML_DSA_65.private_key_bytes, 4032);
        assert_eq!(ML_DSA_87.signature_bytes, 4627);
    }
}

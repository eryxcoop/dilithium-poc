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
pub mod types;

#[cfg(test)]
mod tests;

pub use coefficient::{CANONICAL_MAX, CANONICAL_MIN, CENTERED_MAX, CENTERED_MIN, Coefficient};
pub use encoding::{
    EncodedPrivateKeyParts, EncodedPublicKeyParts, PublicKeyHash, RHO_BYTES, Rho,
    SECRET_KEY_SEED_BYTES, SecretKeySeed, TR_BYTES, bit_pack, bit_unpack, bits_to_bytes,
    bits_to_integer, bytes_to_bits, hint_bit_pack, hint_bit_unpack, integer_to_bytes, pk_decode,
    pk_encode, simple_bit_pack, simple_bit_unpack, sk_decode, sk_encode,
};
pub use error::{DilithiumError, DilithiumResult};
pub use hints::HintsVector;
pub use params::{
    CoreParams, D, EncodedSizes, ML_DSA_44, ML_DSA_65, ML_DSA_87, N, PARAMETER_SETS, ParameterSet,
    ParameterSetId, Q, ZETA,
};
pub use poly::{NttPoly, Poly, PolyMatrix, PolyVector};
pub use round::{Decomposed, Power2Round};
pub use types::{PrivateKey, PublicKey, Signature};

//! Public- and private-key encoders from FIPS 204 Section 7.2.
//!
//! This module implements `pkEncode`, `pkDecode`, `skEncode`, and `skDecode`.
//! Public-key decoding is intended for untrusted inputs and therefore keeps the
//! strict range checks provided by [`super::simple_bit_unpack`]. Private-key
//! decoding is also strict in this POC, even though FIPS 204 notes that
//! `skDecode` is normally run only on trusted inputs.

mod private;
mod public;
mod shared;
mod types;

pub use private::{sk_decode, sk_encode};
pub use public::{pk_decode, pk_encode};
pub use types::{
    EncodedPrivateKeyParts, EncodedPublicKeyParts, PublicKeyHash, RHO_BYTES, Rho,
    SECRET_KEY_SEED_BYTES, SecretKeySeed, TR_BYTES,
};

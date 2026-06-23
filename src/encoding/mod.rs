//! Low-level FIPS 204 encoding helpers.

pub mod bits;
pub mod hint;
pub mod keys;
pub mod poly;

pub use bits::{bits_to_bytes, bits_to_integer, bytes_to_bits, integer_to_bytes};
pub use hint::{hint_bit_pack, hint_bit_unpack};
pub use keys::{
    EncodedPrivateKeyParts, EncodedPublicKeyParts, PublicKeyHash, RHO_BYTES, Rho,
    SECRET_KEY_SEED_BYTES, SecretKeySeed, TR_BYTES, pk_decode, pk_encode, sk_decode, sk_encode,
};
pub use poly::{bit_pack, bit_unpack, simple_bit_pack, simple_bit_unpack};

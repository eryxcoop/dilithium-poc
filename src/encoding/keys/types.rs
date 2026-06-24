//! Decoded key component types and byte-size constants.

use crate::poly::PolyVector;

/// Number of bytes in the FIPS 204 public matrix seed `rho`.
pub const RHO_BYTES: usize = 32;

/// Number of bytes in the FIPS 204 secret-key seed `K`.
pub const SECRET_KEY_SEED_BYTES: usize = 32;

/// Number of bytes in the FIPS 204 public-key hash `tr`.
pub const TR_BYTES: usize = 64;

/// FIPS 204 public matrix seed `rho`.
pub type Rho = [u8; RHO_BYTES];

/// FIPS 204 secret-key seed `K`.
pub type SecretKeySeed = [u8; SECRET_KEY_SEED_BYTES];

/// FIPS 204 public-key hash `tr`.
pub type PublicKeyHash = [u8; TR_BYTES];

/// Decoded components of a FIPS 204 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedPublicKeyParts {
    /// Public matrix seed `ρ`.
    pub rho: Rho,
    /// Rounded public vector `t1` with dimension `k`.
    pub t1: PolyVector,
}

/// Decoded components of a FIPS 204 expanded private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedPrivateKeyParts {
    /// Public matrix seed `ρ`.
    pub rho: Rho,
    /// Secret-key seed `K` used by signing.
    pub secret_key_seed: SecretKeySeed,
    /// Hash of the encoded public key.
    pub tr: PublicKeyHash,
    /// Secret vector `s1` with dimension `l`.
    pub s1: PolyVector,
    /// Secret vector `s2` with dimension `k`.
    pub s2: PolyVector,
    /// Low bits of the public vector `t` with dimension `k`.
    pub t0: PolyVector,
}

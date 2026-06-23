//! Global constants shared by all FIPS 204 ML-DSA parameter sets.

/// Degree of the polynomial ring `R_q = Z_q[X] / (X^256 + 1)`.
pub const N: usize = 256;

/// Prime modulus used by all FIPS 204 ML-DSA parameter sets.
pub const Q: u32 = 8_380_417; // 2^23 - 2^13 + 1

/// FIPS 204 512th root of unity in `Z_q`, used by the NTT.
pub const ZETA: u32 = 1_753;

/// Number of low bits dropped from `t` when forming the public key.
pub const D: u32 = 13;

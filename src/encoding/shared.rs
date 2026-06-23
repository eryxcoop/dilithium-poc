//! Shared helpers for raw FIPS 204 encoders.

use crate::params::N;

/// Returns the exact encoded byte length for one packed polynomial.
///
/// The formula is `ceil(n * bit_width / 8)`. With `n = 256`, this simplifies
/// to `32 * bit_width` bytes for all FIPS 204 polynomial encodings.
///
/// Relevant exact values in this crate are:
///
/// - `packed_poly_bytes(3) = 96` bytes for each ML-DSA-44/87 secret polynomial.
/// - `packed_poly_bytes(4) = 128` bytes for each ML-DSA-65 secret polynomial
///   and each ML-DSA-65/87 `w1` polynomial.
/// - `packed_poly_bytes(6) = 192` bytes for each ML-DSA-44 `w1` polynomial.
/// - `packed_poly_bytes(10) = 320` bytes for each public-key `t1` polynomial.
/// - `packed_poly_bytes(13) = 416` bytes for each private-key `t0` polynomial.
/// - `packed_poly_bytes(18) = 576` bytes for each ML-DSA-44 `z` polynomial.
/// - `packed_poly_bytes(20) = 640` bytes for each ML-DSA-65/87 `z` polynomial.
pub(crate) fn packed_poly_bytes(bit_width: usize) -> usize {
    (N * bit_width).div_ceil(8)
}

/// Returns the bit length of a nonzero unsigned integer.
///
/// Relevant exact values in this crate are:
///
/// - `bit_length(q - 1) = bit_length(8380416) = 23`.
/// - `bit_length(2 * eta) = 3` for `eta = 2`.
/// - `bit_length(2 * eta) = 4` for `eta = 4`.
/// - `bit_length(w1_max) = 6` for ML-DSA-44.
/// - `bit_length(w1_max) = 4` for ML-DSA-65/87.
/// - `bit_length(gamma1 - 1) = 17` for ML-DSA-44.
/// - `bit_length(gamma1 - 1) = 19` for ML-DSA-65/87.
pub(crate) fn bit_length(value: u32) -> usize {
    (u32::BITS - value.leading_zeros()) as usize
}

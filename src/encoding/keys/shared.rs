//! Shared helpers for FIPS 204 key encoders.

use crate::encoding::bit_unpack;
use crate::error::DilithiumResult;
use crate::params::{D, N, Q};
use crate::poly::PolyVector;
pub(super) use crate::validation::{ensure_dimension, ensure_len};

/// Copies a fixed-size byte array out of a checked slice.
pub(super) fn array_from_slice<const LEN: usize>(slice: &[u8]) -> [u8; LEN] {
    let mut array = [0u8; LEN];
    array.copy_from_slice(slice);
    array
}

/// Returns `1023`, the maximum encoded value for a public-key `t1` coefficient.
///
/// FIPS 204 computes this as `2^(bitlen(q - 1) - d) - 1`.
/// With `q = 8380417`, `bitlen(q - 1) = 23`, and `d = 13`, this is
/// `2^10 - 1 = 1023`.
pub(super) fn public_t1_max() -> u32 {
    (1 << public_t1_bit_width()) - 1
}

/// Returns `10`, the bit width used for public-key `t1` coefficients.
///
/// FIPS 204 computes this as `bitlen(q - 1) - d`.
/// With `q = 8380417` and `d = 13`, this is `23 - 13 = 10`.
pub(super) fn public_t1_bit_width() -> usize {
    bit_length(Q - 1) - D as usize
}

/// Returns `4095`, the lower positive bound parameter used by `BitPack(t0, a, b)`.
///
/// FIPS 204 calls `BitPack(t0, 2^(d - 1) - 1, 2^(d - 1))`.
/// With `d = 13`, this returns `2^12 - 1 = 4095`.
pub(super) fn private_t0_a() -> u32 {
    (1 << (D - 1)) - 1
}

/// Returns `4096`, the upper positive bound parameter used by `BitPack(t0, a, b)`.
///
/// FIPS 204 calls `BitPack(t0, 2^(d - 1) - 1, 2^(d - 1))`.
/// With `d = 13`, this returns `2^12 = 4096`.
pub(super) fn private_t0_b() -> u32 {
    1 << (D - 1)
}

/// Returns the exact encoded byte length for one packed polynomial.
///
/// The formula is `ceil(n * bit_width / 8)`. With `n = 256`, this simplifies
/// to `32 * bit_width` bytes. In key encoding this yields:
///
/// - `packed_poly_bytes(10) = 320` bytes for each public-key `t1` polynomial.
/// - `packed_poly_bytes(3) = 96` bytes for each ML-DSA-44/87 secret polynomial.
/// - `packed_poly_bytes(4) = 128` bytes for each ML-DSA-65 secret polynomial.
/// - `packed_poly_bytes(13) = 416` bytes for each private-key `t0` polynomial.
pub(super) fn packed_poly_bytes(bit_width: usize) -> usize {
    (N * bit_width).div_ceil(8)
}

/// Returns the bit length of a nonzero unsigned integer.
///
/// For the FIPS 204 key encoders, the relevant exact values are:
///
/// - `bit_length(q - 1) = bit_length(8380416) = 23`.
/// - `bit_length(2 * eta) = 3` for `eta = 2`.
/// - `bit_length(2 * eta) = 4` for `eta = 4`.
pub(super) fn bit_length(value: u32) -> usize {
    (u32::BITS - value.leading_zeros()) as usize
}

/// Decodes a consecutive packed vector using FIPS 204 `BitUnpack`.
pub(super) fn unpack_vector(
    encoding: &[u8],
    offset: &mut usize,
    dimension: usize,
    poly_bytes: usize,
    a: u32,
    b: u32,
) -> DilithiumResult<PolyVector> {
    let mut polys = Vec::with_capacity(dimension);

    for _ in 0..dimension {
        let end = *offset + poly_bytes;
        polys.push(bit_unpack(&encoding[*offset..end], a, b)?);
        *offset = end;
    }

    PolyVector::from_polys(dimension, polys)
}

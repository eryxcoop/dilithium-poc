//! Shared helpers for FIPS 204 key encoders.

use crate::encoding::bit_unpack;
pub(super) use crate::encoding::shared::{bit_length, packed_poly_bytes};
use crate::error::DilithiumResult;
use crate::params::{D, Q};
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

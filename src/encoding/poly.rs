//! Polynomial packing and unpacking helpers from FIPS 204 Section 7.2.
//!
//! These routines are the low-level helpers used by higher-level ML-DSA encoders.
//! They keep the same domain/range constraints and bit-width layout defined by the
//! standard and perform strict malformed-input checks for untrusted inputs.

use crate::coefficient::Coefficient;
use crate::encoding::shared::{bit_length, packed_poly_bytes};
use crate::encoding::{bits_to_bytes, bits_to_integer, bytes_to_bits};
use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{N, Q};
use crate::poly::Poly;
use crate::validation::{
    ensure_i32_range, ensure_len, ensure_positive_u32_bound, ensure_u32_range,
};

/// Encodes one polynomial using the `SimpleBitPack` procedure.
///
/// This is FIPS 204 Algorithm 16.
///
/// The polynomial coefficients are interpreted as unsigned integers.
pub fn simple_bit_pack(polynomial: &Poly, max_value: u32) -> DilithiumResult<Vec<u8>> {
    ensure_positive_u32_bound("simple bit pack bound", max_value)?;

    let width = bit_length(max_value);
    let mut bits = Vec::with_capacity(N * width);

    for &coefficient in polynomial.coeffs() {
        let value = coefficient.value() as u32;
        ensure_u32_range("packed coefficient", value, 0, max_value)?;
        append_integer_bits(&mut bits, value as u64, width);
    }

    bits_to_bytes(&bits)
}

/// Encodes one polynomial using the `BitPack` procedure.
///
/// This is FIPS 204 Algorithm 17.
///
/// Each coefficient is first interpreted in centered integer form and must lie in
/// `[-a, b]`.
pub fn bit_pack(polynomial: &Poly, a: u32, b: u32) -> DilithiumResult<Vec<u8>> {
    let total = a.checked_add(b).ok_or(DilithiumError::MalformedEncoding(
        "bit pack bounds overflow",
    ))?;
    ensure_positive_u32_bound("bit pack bound", total)?;

    let width = bit_length(total);
    let mut bits = Vec::with_capacity(N * width);

    for &coefficient in polynomial.coeffs() {
        let signed = Coefficient::centered(coefficient.value() as i64).value();
        ensure_i32_range("packed coefficient", signed, -(a as i32), b as i32)?;
        let encoded = (b as i64) - (signed as i64);
        append_integer_bits(&mut bits, encoded as u64, width);
    }

    bits_to_bytes(&bits)
}

/// Reverses `simple_bit_pack` and rejects out-of-range coefficients.
///
/// This follows FIPS 204 Algorithm 18 with an additional conformance check for
/// malformed inputs: every decoded value must lie in `[0, max_value]`.
pub fn simple_bit_unpack(bytes: &[u8], max_value: u32) -> DilithiumResult<Poly> {
    ensure_positive_u32_bound("simple bit unpack bound", max_value)?;

    let width = bit_length(max_value);
    ensure_packed_length("simple bit packed polynomial", bytes.len(), width)?;

    let bits = bytes_to_bits(bytes);
    let mut coeffs = [Coefficient::default(); N];

    for (index, coefficient) in coeffs.iter_mut().enumerate() {
        let start = index * width;
        let end = start + width;
        let value = bits_to_integer(&bits[start..end])?;

        if value > max_value as u64 {
            return Err(DilithiumError::MalformedEncoding(
                "simple bit unpack produced out-of-range coefficient",
            ));
        }

        *coefficient = Coefficient::from(value as i32);
    }

    Ok(Poly::from_coeffs(coeffs))
}

/// Reverses `bit_pack` and rejects out-of-range coefficients.
///
/// This follows FIPS 204 Algorithm 19 with an additional conformance check for
/// malformed inputs: every decoded value must lie in `[-a, b]`.
pub fn bit_unpack(bytes: &[u8], a: u32, b: u32) -> DilithiumResult<Poly> {
    let total = a.checked_add(b).ok_or(DilithiumError::MalformedEncoding(
        "bit unpack bounds overflow",
    ))?;
    ensure_positive_u32_bound("bit unpack bound", total)?;

    let width = bit_length(total);
    ensure_packed_length("bit packed polynomial", bytes.len(), width)?;

    let bits = bytes_to_bits(bytes);
    let mut coeffs = [Coefficient::default(); N];

    for (index, coefficient) in coeffs.iter_mut().enumerate() {
        let start = index * width;
        let end = start + width;
        let unpacked = bits_to_integer(&bits[start..end])?;
        let value = (b as i64) - (unpacked as i64);
        let signed = if value < -(Q as i64) / 2 {
            value + Q as i64
        } else {
            value
        };

        if value < -(a as i64) || value > b as i64 {
            return Err(DilithiumError::MalformedEncoding(
                "bit unpack produced out-of-range coefficient",
            ));
        }

        *coefficient = Coefficient::from(signed as i32);
    }

    Ok(Poly::from_coeffs(coeffs))
}

fn append_integer_bits(bits: &mut Vec<u8>, value: u64, width: usize) {
    for bit_index in 0..width {
        bits.push(((value >> bit_index) & 1) as u8);
    }
}

fn ensure_packed_length(
    item: &'static str,
    actual_bytes: usize,
    bit_width: usize,
) -> DilithiumResult<()> {
    let expected = packed_poly_bytes(bit_width);
    ensure_len(item, expected, actual_bytes)
}

//! Bit- and byte-level packing helpers from FIPS 204 Section 7.2.
//!
//! All conversions in this module use the little-endian conventions from the
//! standard:
//!
//! - bit strings are interpreted with the least significant bit first;
//! - byte strings are interpreted with the least significant byte first.
//!
//! This module only contains bit/byte conversion primitives.

use crate::error::{DilithiumError, DilithiumResult};

/// Computes the integer value expressed by a bit string in little-endian order.
///
/// This is FIPS 204 Algorithm 10, `BitsToInteger(y, alpha)`.
///
/// The input slice must contain only `0` and `1`.
pub fn bits_to_integer(bits: &[u8]) -> DilithiumResult<u64> {
    let mut value = 0u64;

    for (index, &bit) in bits.iter().enumerate() {
        ensure_bit(bit)?;
        if index >= u64::BITS as usize {
            return Err(DilithiumError::ValueOutOfRange {
                item: "bit string length",
                min: 0,
                max: u64::BITS as i64,
                actual: bits.len() as i64,
            });
        }
        value |= (bit as u64) << index;
    }

    Ok(value)
}

/// Computes the base-256 representation of `value` modulo `256^byte_len`.
///
/// This is FIPS 204 Algorithm 11, `IntegerToBytes(x, alpha)`.
pub fn integer_to_bytes(value: u64, byte_len: usize) -> Vec<u8> {
    let mut remaining = value;
    let mut bytes = Vec::with_capacity(byte_len);

    for _ in 0..byte_len {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }

    bytes
}

/// Converts a bit string into a byte string using little-endian order.
///
/// This is FIPS 204 Algorithm 12, `BitsToBytes(y)`.
///
/// The input slice must contain only `0` and `1`.
pub fn bits_to_bytes(bits: &[u8]) -> DilithiumResult<Vec<u8>> {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];

    for (index, &bit) in bits.iter().enumerate() {
        ensure_bit(bit)?;
        bytes[index / 8] |= bit << (index % 8);
    }

    Ok(bytes)
}

/// Converts a byte string into a bit string using little-endian order.
///
/// This is FIPS 204 Algorithm 13, `BytesToBits(z)`.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);

    for &byte in bytes {
        let mut value = byte;
        for _ in 0..8 {
            bits.push(value & 1);
            value >>= 1;
        }
    }

    bits
}

fn ensure_bit(bit: u8) -> DilithiumResult<()> {
    if bit <= 1 {
        Ok(())
    } else {
        Err(DilithiumError::ValueOutOfRange {
            item: "bit",
            min: 0,
            max: 1,
            actual: bit as i64,
        })
    }
}

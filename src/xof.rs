//! SHAKE extendable-output functions used by FIPS 204.
//!
//! FIPS 204 uses two XOFs:
//! - `G`, instantiated with SHAKE128;
//! - `H`, instantiated with SHAKE256.
//!
//! This module exposes fixed-output helpers for callers that need the
//! `XOF(input, out_len)` form from the standard and keeps incremental readers
//! available internally for rejection-sampling algorithms.
//!
//! References:
//! - FIPS 202 defines SHAKE128 and SHAKE256:
//!   <https://doi.org/10.6028/NIST.FIPS.202>
//! - FIPS 204 defines their use as `G` and `H` in ML-DSA:
//!   <https://doi.org/10.6028/NIST.FIPS.204>

use shake::digest::{ExtendableOutput, Update, XofReader};
use shake::{Shake128, Shake256};

/// Computes `SHAKE128(input, output_len)`.
pub fn shake128(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut reader = shake128_reader(input);
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// Computes `SHAKE256(input, output_len)`.
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut reader = shake256_reader(input);
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

pub(crate) fn shake128_reader(input: &[u8]) -> impl XofReader {
    let mut hasher = Shake128::default();
    hasher.update(input);
    hasher.finalize_xof()
}

pub(crate) fn shake256_reader(input: &[u8]) -> impl XofReader {
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize_xof()
}

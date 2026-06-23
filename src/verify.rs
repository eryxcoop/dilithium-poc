//! Verification entry points.
//!
//! Full ML-DSA verification is planned for M4. The M2-facing helper below
//! implements the FIPS 204 length rejection boundary so callers never accept
//! flexible public-key or signature lengths.

use crate::params::ParameterSet;

/// Returns `false` unless `public_key` and `signature` have exact FIPS 204 sizes.
///
/// This is the M2 length-check boundary required before full verification is
/// implemented. A return value of `true` only means the byte strings have the
/// correct size; it does not mean the signature is cryptographically valid.
pub fn verify_lengths(public_key: &[u8], signature: &[u8], parameter_set: ParameterSet) -> bool {
    public_key.len() == parameter_set.sizes.public_key_bytes
        && signature.len() == parameter_set.sizes.signature_bytes
}

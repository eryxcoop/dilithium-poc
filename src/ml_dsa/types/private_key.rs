//! Raw FIPS 204 expanded private-key wrapper.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::validation::ensure_len;

/// Raw FIPS 204 expanded private key tagged with its ML-DSA parameter set.
///
/// RFC 9881 also defines a compact 32-byte seed private-key format for PKIX.
/// This type represents the expanded FIPS 204 `skEncode(...)` byte string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Builds a private key from a raw FIPS 204 expanded private-key encoding.
    ///
    /// Returns [`crate::error::DilithiumError::InvalidLength`] unless `bytes.len()` exactly
    /// matches `parameter_set.sizes.private_key_bytes`.
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> DilithiumResult<Self> {
        ensure_len(
            "private key",
            parameter_set.sizes.private_key_bytes,
            bytes.len(),
        )?;
        Ok(Self {
            parameter_set,
            bytes,
        })
    }

    /// Returns the ML-DSA parameter set associated with this key.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Returns the raw FIPS 204 expanded private-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

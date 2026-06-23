//! Raw FIPS 204 public-key wrapper.

use crate::error::Result;
use crate::params::ParameterSet;
use crate::types::validation::ensure_len;

/// Raw FIPS 204 public key tagged with its ML-DSA parameter set.
///
/// The byte string is expected to be the `pkEncode(rho, t1)` representation
/// from FIPS 204, not a PKIX `SubjectPublicKeyInfo` wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Builds a public key from a raw FIPS 204 public-key encoding.
    ///
    /// Returns [`crate::Error::InvalidLength`] unless `bytes.len()` exactly
    /// matches `parameter_set.sizes.public_key_bytes`.
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> Result<Self> {
        ensure_len(
            "public key",
            parameter_set.sizes.public_key_bytes,
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

    /// Returns the raw FIPS 204 public-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

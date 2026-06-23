//! Raw FIPS 204 signature wrapper.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::types::validation::ensure_len;

/// Raw FIPS 204 signature tagged with its ML-DSA parameter set.
///
/// The byte string is expected to be the `sigEncode(c_tilde, z, h)`
/// representation from FIPS 204.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

impl Signature {
    /// Builds a signature from a raw FIPS 204 signature encoding.
    ///
    /// Returns [`crate::DilithiumError::InvalidLength`] unless `bytes.len()` exactly
    /// matches `parameter_set.sizes.signature_bytes`.
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> DilithiumResult<Self> {
        ensure_len(
            "signature",
            parameter_set.sizes.signature_bytes,
            bytes.len(),
        )?;
        Ok(Self {
            parameter_set,
            bytes,
        })
    }

    /// Returns the ML-DSA parameter set associated with this signature.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Returns the raw FIPS 204 signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

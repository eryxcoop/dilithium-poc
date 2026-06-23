//! Error types for the ML-DSA POC.

/// Crate-local result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by the POC API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A raw FIPS 204 byte string did not have the exact size required
    /// by its parameter set.
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
        /// Human-readable item name, such as `"public key"` or `"signature"`.
        item: &'static str,
    },
    /// The requested ML-DSA parameter set is unknown or not enabled.
    InvalidParameterSet,
    /// Placeholder for functionality planned in later milestones.
    Unsupported(&'static str),
}

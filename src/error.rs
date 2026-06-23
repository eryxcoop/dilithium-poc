//! Error types for the ML-DSA POC.

/// Crate-local result type.
pub type DilithiumResult<T> = core::result::Result<T, DilithiumError>;

/// Errors returned by the POC API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DilithiumError {
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
    /// Two algebraic objects do not agree on the shape required by the operation.
    DimensionMismatch {
        /// Expected dimension or item count.
        expected: usize,
        /// Actual dimension or item count.
        actual: usize,
        /// Human-readable item name, such as `"polynomial vector dimension"`.
        item: &'static str,
    },
    /// An encoded value was malformed or violated a FIPS 204 packing rule.
    MalformedEncoding(&'static str),
    /// A numeric value did not fit within the range required by the operation.
    ValueOutOfRange {
        /// Human-readable item name, such as `"packed coefficient"` or `"bit"`.
        item: &'static str,
        /// Inclusive minimum allowed value.
        min: i64,
        /// Inclusive maximum allowed value.
        max: i64,
        /// Actual numeric value observed.
        actual: i64,
    },
    /// The requested ML-DSA parameter set is unknown or not enabled.
    InvalidParameterSet,
    /// Placeholder for functionality planned in later milestones.
    Unsupported(&'static str),
}

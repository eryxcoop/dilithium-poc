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
    /// A DER/PKIX value was malformed or violated RFC 9881.
    MalformedPkix(&'static str),
    /// A PKIX private-key package carried inconsistent redundant material.
    InconsistentPrivateKey(&'static str),
    /// A PKIX `keyUsage` extension violates RFC 9881's ML-DSA rules.
    InvalidKeyUsage(&'static str),
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
    /// A caller requested an optional FIPS limit smaller than the minimum
    /// bound allowed by Table 3.
    LimitTooSmall {
        /// Human-readable algorithm name.
        algorithm: &'static str,
        /// Human-readable limit kind, such as `"loop iterations"` or `"xof bytes"`.
        limit_kind: &'static str,
        /// Minimum limit allowed by FIPS 204 Table 3.
        minimum: usize,
        /// Actual limit requested by the caller.
        actual: usize,
    },
    /// An optional Table 3 limit was reached while sampling.
    SamplingLimitExceeded {
        /// Human-readable algorithm name.
        algorithm: &'static str,
        /// Human-readable limit kind, such as `"loop iterations"` or `"xof bytes"`.
        limit_kind: &'static str,
        /// Effective limit that was reached.
        limit: usize,
    },
    /// Placeholder for functionality planned in later milestones.
    Unsupported(&'static str),
}

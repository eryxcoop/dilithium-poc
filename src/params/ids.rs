//! Stable identifiers for FIPS 204 ML-DSA parameter sets.

/// Identifier for one of the three ML-DSA parameter sets approved by FIPS 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterSetId {
    /// ML-DSA-44, corresponding to NIST PQC security category 2.
    MlDsa44,
    /// ML-DSA-65, corresponding to NIST PQC security category 3.
    MlDsa65,
    /// ML-DSA-87, corresponding to NIST PQC security category 5.
    MlDsa87,
}

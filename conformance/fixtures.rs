//! Embedded ACVP JSON fixtures.

/// ACVP keyGen prompt vectors.
pub(super) const KEYGEN_PROMPT: &str = include_str!("acvp/ML-DSA-keyGen-FIPS204/prompt.json");

/// ACVP keyGen expected results.
pub(super) const KEYGEN_EXPECTED: &str =
    include_str!("acvp/ML-DSA-keyGen-FIPS204/expectedResults.json");

/// ACVP sigGen prompt vectors.
pub(super) const SIGGEN_PROMPT: &str = include_str!("acvp/ML-DSA-sigGen-FIPS204/prompt.json");

/// ACVP sigGen expected results.
pub(super) const SIGGEN_EXPECTED: &str =
    include_str!("acvp/ML-DSA-sigGen-FIPS204/expectedResults.json");

/// ACVP sigVer prompt vectors.
pub(super) const SIGVER_PROMPT: &str = include_str!("acvp/ML-DSA-sigVer-FIPS204/prompt.json");

/// ACVP sigVer expected results.
pub(super) const SIGVER_EXPECTED: &str =
    include_str!("acvp/ML-DSA-sigVer-FIPS204/expectedResults.json");

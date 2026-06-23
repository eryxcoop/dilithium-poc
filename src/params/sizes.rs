//! Encoding sizes for raw FIPS 204 ML-DSA objects.

/// Raw FIPS 204 encoding sizes for one ML-DSA parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedSizes {
    /// Raw FIPS 204 public-key encoding size in bytes.
    pub public_key_bytes: usize,
    /// Raw FIPS 204 expanded private-key encoding size in bytes.
    pub private_key_bytes: usize,
    /// Raw FIPS 204 signature encoding size in bytes.
    pub signature_bytes: usize,
}

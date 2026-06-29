//! Public CMS option types.

use crate::pkix::cms::digest::CmsDigestAlgorithm;

/// Controls whether the generated CMS `SignerInfo` includes signed attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmsSignedAttrs {
    /// Include `signedAttrs` and sign their DER `SET OF` encoding.
    Present,
    /// Omit `signedAttrs` and sign the content octets directly.
    Absent,
}

/// Options for generating a minimal RFC 9882 ML-DSA `SignedData`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MldsaCmsSignedDataOptions {
    /// Digest algorithm used in `digestAlgorithm` and `message-digest`.
    pub digest_algorithm: CmsDigestAlgorithm,
    /// Whether `SignerInfo.signedAttrs` should be present.
    pub signed_attrs: CmsSignedAttrs,
    /// Whether the content octets should be embedded in `encapContentInfo`.
    pub encapsulate_content: bool,
    /// Whether generated signed attributes include `CMSAlgorithmProtection`.
    pub include_algorithm_protection: bool,
}

impl Default for MldsaCmsSignedDataOptions {
    fn default() -> Self {
        Self {
            digest_algorithm: CmsDigestAlgorithm::Sha512,
            signed_attrs: CmsSignedAttrs::Present,
            encapsulate_content: true,
            include_algorithm_protection: true,
        }
    }
}

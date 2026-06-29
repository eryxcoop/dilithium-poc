//! Minimal RFC 9882 CMS `SignedData` support for pure ML-DSA.
//!
//! RFC 9882 specifies how ML-DSA signatures are carried in CMS. This module is
//! intentionally narrower than a general-purpose CMS implementation: it emits
//! and verifies a single-signer `ContentInfo` containing `SignedData`, with the
//! ML-DSA pure-mode context fixed to the empty string (`ctx = ""`).
//!
//! The important CMS boundary is the data that ML-DSA signs:
//!
//! - without `signedAttrs`, ML-DSA signs the raw `eContent` octets;
//! - with `signedAttrs`, ML-DSA signs the complete DER `SET OF` encoding of
//!   `SignedAttrs`, not the implicit `[0]` field encoding stored in
//!   `SignerInfo`.
//!
//! # Scope Boundary
//!
//! This is an RFC 9882-focused profile, not a complete RFC 5652 CMS stack. The
//! module deliberately avoids general certificate path processing, CRL support,
//! multi-signer selection, arbitrary `SignerIdentifier` resolution, and full
//! attribute semantics. Callers provide the ML-DSA public key used for
//! verification instead of asking this module to discover it from embedded
//! certificates.
//!
//! A fuller interoperability layer would likely add enough X.509/CMS parsing to
//! verify the Appendix B examples from RFC 9882 using the certificates from
//! RFC 9881, support real issuer-and-serial or subject-key-identifier signer
//! lookup, validate `CMSAlgorithmProtection` semantically, and handle multiple
//! signers. A general CMS implementation would be a substantially larger effort
//! and should probably reuse or wrap a dedicated CMS crate rather than growing
//! this educational ML-DSA POC into a broad ASN.1/CMS library.

mod algorithm;
mod attributes;
mod der;
mod digest;
mod encode;
mod oid;
mod parse;
mod types;
mod verify;

pub use algorithm::{cms_digest_algorithm_der, cms_signature_algorithm_der};
pub use attributes::cms_signed_attrs_to_be_signed_der;
pub use digest::CmsDigestAlgorithm;
pub use encode::encode_mldsa_signed_data;
pub use oid::{
    ID_CMS_ALGORITHM_PROTECTION_ATTR, ID_CONTENT_TYPE_ATTR, ID_DATA, ID_MESSAGE_DIGEST_ATTR,
    ID_SIGNED_DATA,
};
pub use types::{CmsSignedAttrs, MldsaCmsSignedDataOptions};
pub use verify::verify_mldsa_signed_data;

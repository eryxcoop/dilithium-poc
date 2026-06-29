//! CMS object identifiers used by the RFC 9882 profile.

use der::asn1::ObjectIdentifier;

/// CMS `id-data` content type: `1.2.840.113549.1.7.1`.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// CMS `id-signedData` content type: `1.2.840.113549.1.7.2`.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// CMS `contentType` signed attribute: `1.2.840.113549.1.9.3`.
pub const ID_CONTENT_TYPE_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// CMS `messageDigest` signed attribute: `1.2.840.113549.1.9.4`.
pub const ID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// CMS `CMSAlgorithmProtection` signed attribute: `1.2.840.113549.1.9.52`.
pub const ID_CMS_ALGORITHM_PROTECTION_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.52");

pub(crate) const ID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(crate) const ID_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub(crate) const ID_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
pub(crate) const ID_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
pub(crate) const ID_SHA3_384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");
pub(crate) const ID_SHA3_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");
pub(crate) const ID_SHAKE128: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.11");
pub(crate) const ID_SHAKE256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.12");

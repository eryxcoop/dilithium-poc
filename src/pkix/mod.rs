//! RFC 9881 PKIX/X.509 wrappers for pure ML-DSA.
//!
//! FIPS 204 defines the raw ML-DSA public key, expanded private key, and
//! signature byte strings. RFC 9881 defines how those byte strings are carried
//! in PKIX structures:
//!
//! - `AlgorithmIdentifier` is `SEQUENCE { algorithm OBJECT IDENTIFIER }` with
//!   the `parameters` field absent. A DER `NULL` is not equivalent here.
//! - `SubjectPublicKeyInfo.subjectPublicKey` is a BIT STRING containing the raw
//!   FIPS 204 public key bytes with no extra ASN.1 wrapper.
//! - `OneAsymmetricKey.privateKey` is an OCTET STRING containing one
//!   DER-encoded ML-DSA private-key CHOICE: seed `[0]`, expanded key
//!   `OCTET STRING`, or `both` `SEQUENCE`.
//!
//! This module intentionally keeps these DER wrappers outside [`crate::ml_dsa`]
//! so the algorithmic FIPS path remains separate from transport encoding.

mod algorithm;
mod key_usage;
mod oid;
mod private_key;
mod spki;

pub use algorithm::{algorithm_identifier_der, decode_algorithm_identifier};
pub use key_usage::{KeyUsage, validate_key_usage};
pub use oid::{
    ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87, oid_for_parameter_set, parameter_set_for_oid,
};
pub use private_key::{
    ConsistencyCheck, DecodedOneAsymmetricKey, PkixPrivateKey, encode_one_asymmetric_key,
    encode_private_key_choice, parse_one_asymmetric_key, parse_one_asymmetric_key_with_options,
    parse_private_key_choice, parse_private_key_choice_with_options,
};
pub use spki::{decode_subject_public_key_info, subject_public_key_info_der};

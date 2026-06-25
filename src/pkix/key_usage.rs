//! RFC 9881 validation for X.509 `keyUsage` bits.

use crate::error::{DilithiumError, DilithiumResult};

/// X.509 `keyUsage` bits relevant to RFC 9881 ML-DSA validation.
///
/// The type intentionally mirrors the named RFC 5280 bits instead of exposing
/// raw bit positions. RFC 9881 permits signature/cert/CRL uses and prohibits
/// key establishment or data-encryption uses for ML-DSA public keys.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyUsage {
    /// `digitalSignature` usage bit.
    pub digital_signature: bool,
    /// `nonRepudiation` / `contentCommitment` usage bit.
    pub non_repudiation: bool,
    /// `keyEncipherment` usage bit.
    pub key_encipherment: bool,
    /// `dataEncipherment` usage bit.
    pub data_encipherment: bool,
    /// `keyAgreement` usage bit.
    pub key_agreement: bool,
    /// `keyCertSign` usage bit.
    pub key_cert_sign: bool,
    /// `cRLSign` usage bit.
    pub crl_sign: bool,
    /// `encipherOnly` usage bit.
    pub encipher_only: bool,
    /// `decipherOnly` usage bit.
    pub decipher_only: bool,
}

impl KeyUsage {
    /// Returns `true` when at least one RFC 9881 permitted ML-DSA use is set.
    pub fn has_mldsa_allowed_usage(self) -> bool {
        self.digital_signature || self.non_repudiation || self.key_cert_sign || self.crl_sign
    }

    /// Returns `true` when any RFC 9881 forbidden ML-DSA use is set.
    pub fn has_mldsa_forbidden_usage(self) -> bool {
        self.key_encipherment
            || self.data_encipherment
            || self.key_agreement
            || self.encipher_only
            || self.decipher_only
    }
}

/// Validates RFC 9881 `keyUsage` requirements for an ML-DSA public key.
///
/// If a `keyUsage` extension is present, RFC 9881 requires at least one of
/// `digitalSignature`, `nonRepudiation`, `keyCertSign`, or `cRLSign`, and
/// forbids `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
/// `encipherOnly`, and `decipherOnly`.
pub fn validate_key_usage(key_usage: KeyUsage) -> DilithiumResult<()> {
    if !key_usage.has_mldsa_allowed_usage() {
        return Err(DilithiumError::InvalidKeyUsage(
            "ML-DSA keyUsage needs at least one signature/cert/CRL bit",
        ));
    }
    if key_usage.has_mldsa_forbidden_usage() {
        return Err(DilithiumError::InvalidKeyUsage(
            "ML-DSA keyUsage forbids key establishment and data encryption bits",
        ));
    }
    Ok(())
}

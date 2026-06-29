//! `SubjectPublicKeyInfo` encoding for RFC 9881 ML-DSA public keys.

use der::asn1::BitStringRef;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoRef;

use crate::error::{DilithiumError, DilithiumResult};
use crate::ml_dsa::PublicKey;
use crate::pkix::algorithm::MldsaAlgorithmIdentifier;

pub(crate) struct MldsaSubjectPublicKeyInfo;

impl MldsaSubjectPublicKeyInfo {
    pub(crate) fn encode(public_key: &PublicKey) -> DilithiumResult<Vec<u8>> {
        let subject_public_key = BitStringRef::from_bytes(public_key.as_bytes())
            .map_err(|_| DilithiumError::MalformedPkix("invalid SPKI BIT STRING"))?;
        let spki = SubjectPublicKeyInfoRef {
            algorithm: MldsaAlgorithmIdentifier::new(public_key.parameter_set())?.as_ref(),
            subject_public_key,
        };
        spki.to_der()
            .map_err(|_| DilithiumError::MalformedPkix("failed to encode SubjectPublicKeyInfo"))
    }

    pub(crate) fn decode(der: &[u8]) -> DilithiumResult<PublicKey> {
        let spki = SubjectPublicKeyInfoRef::from_der(der)
            .map_err(|_| DilithiumError::MalformedPkix("malformed SubjectPublicKeyInfo DER"))?;
        let algorithm = MldsaAlgorithmIdentifier::from_ref(&spki.algorithm)?;
        let parameter_set = algorithm.parameter_set()?;
        let public_key =
            spki.subject_public_key
                .as_bytes()
                .ok_or(DilithiumError::MalformedPkix(
                    "ML-DSA subjectPublicKey must be byte-aligned",
                ))?;
        PublicKey::from_raw(parameter_set, public_key.to_vec())
    }
}

/// Encodes a raw FIPS 204 public key as RFC 9881 `SubjectPublicKeyInfo` DER.
///
/// The `subjectPublicKey` BIT STRING contains the raw `pkEncode(ρ, t1)` bytes.
/// RFC 9881 explicitly says there is no extra ASN.1 wrapping inside that BIT
/// STRING.
pub fn subject_public_key_info_der(public_key: &PublicKey) -> DilithiumResult<Vec<u8>> {
    MldsaSubjectPublicKeyInfo::encode(public_key)
}

/// Decodes an RFC 9881 `SubjectPublicKeyInfo` into a raw FIPS 204 public key.
///
/// This rejects unknown OIDs, present `AlgorithmIdentifier.parameters`, BIT
/// STRINGs with unused bits, and raw public-key byte strings whose size does
/// not match the OID-selected ML-DSA parameter set.
pub fn decode_subject_public_key_info(der: &[u8]) -> DilithiumResult<PublicKey> {
    MldsaSubjectPublicKeyInfo::decode(der)
}

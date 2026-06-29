//! CMS `AlgorithmIdentifier` encoding and strict decoding.

use der::asn1::ObjectIdentifier;

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::ParameterSet;

use crate::pkix::algorithm::MldsaAlgorithmIdentifier;
use crate::pkix::cms::der::{DerElement, DerReader, DerValue};
use crate::pkix::cms::digest::CmsDigestAlgorithm;
use crate::pkix::oid::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87, parameter_set_for_oid};

pub(crate) struct AlgorithmIdentifierDer {
    bytes: Vec<u8>,
}

impl AlgorithmIdentifierDer {
    pub(crate) fn for_signature(parameter_set: ParameterSet) -> DilithiumResult<Self> {
        let bytes = MldsaAlgorithmIdentifier::new(parameter_set)?.to_der()?;
        Ok(Self { bytes })
    }

    pub(crate) fn for_digest(digest: CmsDigestAlgorithm) -> DilithiumResult<Self> {
        Ok(Self {
            bytes: DerValue::sequence(&[DerValue::oid(digest.oid())?.into_vec()]).into_vec(),
        })
    }

    pub(crate) fn decode_digest(der: &[u8]) -> DilithiumResult<CmsDigestAlgorithm> {
        let alg = Self::decode_oid_only(der)?;
        CmsDigestAlgorithm::from_oid(alg)
    }

    pub(crate) fn decode_signature(der: &[u8]) -> DilithiumResult<ParameterSet> {
        let oid = Self::decode_oid_only(der)?;
        match oid {
            ID_ML_DSA_44 | ID_ML_DSA_65 | ID_ML_DSA_87 => parameter_set_for_oid(oid),
            _ => Err(DilithiumError::InvalidParameterSet),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    fn decode_oid_only(der: &[u8]) -> DilithiumResult<ObjectIdentifier> {
        let alg = DerElement::expect_single(der)?;
        if alg.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix(
                "AlgorithmIdentifier must be SEQUENCE",
            ));
        }
        let mut fields = DerReader::new(alg.value);
        let oid = fields.next_oid()?;
        if !fields.is_empty() {
            return Err(DilithiumError::MalformedPkix(
                "AlgorithmIdentifier parameters must be absent",
            ));
        }
        Ok(oid)
    }
}

/// Encodes an RFC 9882 ML-DSA signature `AlgorithmIdentifier`.
///
/// The result is a DER `AlgorithmIdentifier` whose `parameters` component is
/// absent, reusing the OIDs assigned by RFC 9881 and referenced by RFC 9882.
pub fn cms_signature_algorithm_der(parameter_set: ParameterSet) -> DilithiumResult<Vec<u8>> {
    AlgorithmIdentifierDer::for_signature(parameter_set).map(AlgorithmIdentifierDer::into_vec)
}

/// Encodes a CMS digest `AlgorithmIdentifier` with absent parameters.
pub fn cms_digest_algorithm_der(digest: CmsDigestAlgorithm) -> DilithiumResult<Vec<u8>> {
    AlgorithmIdentifierDer::for_digest(digest).map(AlgorithmIdentifierDer::into_vec)
}

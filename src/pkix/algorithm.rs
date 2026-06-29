//! `AlgorithmIdentifier` encoding for RFC 9881 ML-DSA OIDs.

use der::{Decode, Encode};
use spki::AlgorithmIdentifierRef;

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::ParameterSet;
use crate::pkix::oid::MldsaOid;

pub(crate) struct MldsaAlgorithmIdentifier {
    algorithm: AlgorithmIdentifierRef<'static>,
}

impl MldsaAlgorithmIdentifier {
    pub(crate) fn new(parameter_set: ParameterSet) -> DilithiumResult<Self> {
        Ok(Self {
            algorithm: AlgorithmIdentifierRef {
                oid: MldsaOid::for_parameter_set(parameter_set)?,
                parameters: None,
            },
        })
    }

    pub(crate) fn from_ref(algorithm: &AlgorithmIdentifierRef<'_>) -> DilithiumResult<Self> {
        Self::validate_absent_parameters(algorithm)?;
        let parameter_set = MldsaOid::parameter_set(algorithm.oid)?;
        Self::new(parameter_set)
    }

    pub(crate) fn validate_absent_parameters(
        algorithm: &AlgorithmIdentifierRef<'_>,
    ) -> DilithiumResult<()> {
        if algorithm.parameters.is_some() {
            return Err(DilithiumError::MalformedPkix(
                "ML-DSA AlgorithmIdentifier parameters must be absent",
            ));
        }
        Ok(())
    }

    pub(crate) fn parameter_set(&self) -> DilithiumResult<ParameterSet> {
        MldsaOid::parameter_set(self.algorithm.oid)
    }

    pub(crate) fn as_ref(&self) -> AlgorithmIdentifierRef<'static> {
        self.algorithm
    }

    pub(crate) fn to_der(&self) -> DilithiumResult<Vec<u8>> {
        self.algorithm
            .to_der()
            .map_err(|_| DilithiumError::MalformedPkix("failed to encode AlgorithmIdentifier"))
    }

    pub(crate) fn decode_der(der: &[u8]) -> DilithiumResult<Self> {
        let algorithm = AlgorithmIdentifierRef::from_der(der)
            .map_err(|_| DilithiumError::MalformedPkix("malformed AlgorithmIdentifier DER"))?;
        Self::from_ref(&algorithm)
    }
}

/// Encodes the RFC 9881 ML-DSA `AlgorithmIdentifier` as DER.
///
/// RFC 9881 Section 2 requires the `parameters` component to be absent for
/// `id-ml-dsa-44`, `id-ml-dsa-65`, and `id-ml-dsa-87`. This function therefore
/// emits a one-component sequence containing only the OID.
pub fn algorithm_identifier_der(parameter_set: ParameterSet) -> DilithiumResult<Vec<u8>> {
    MldsaAlgorithmIdentifier::new(parameter_set)?.to_der()
}

/// Decodes and validates an RFC 9881 ML-DSA `AlgorithmIdentifier`.
///
/// A DER `NULL` or any other parameter value is rejected. This is stricter than
/// generic SPKI helpers that sometimes normalize `NULL` and absent parameters:
/// RFC 9881 says the field "MUST be absent".
pub fn decode_algorithm_identifier(der: &[u8]) -> DilithiumResult<ParameterSet> {
    MldsaAlgorithmIdentifier::decode_der(der)?.parameter_set()
}

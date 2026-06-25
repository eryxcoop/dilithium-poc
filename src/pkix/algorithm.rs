//! `AlgorithmIdentifier` encoding for RFC 9881 ML-DSA OIDs.

use der::{Decode, Encode};
use spki::AlgorithmIdentifierRef;

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::ParameterSet;

use super::oid::{oid_for_parameter_set, parameter_set_for_oid};

pub(crate) fn algorithm_identifier(
    parameter_set: ParameterSet,
) -> DilithiumResult<AlgorithmIdentifierRef<'static>> {
    Ok(AlgorithmIdentifierRef {
        oid: oid_for_parameter_set(parameter_set)?,
        parameters: None,
    })
}

/// Encodes the RFC 9881 ML-DSA `AlgorithmIdentifier` as DER.
///
/// RFC 9881 Section 2 requires the `parameters` component to be absent for
/// `id-ml-dsa-44`, `id-ml-dsa-65`, and `id-ml-dsa-87`. This function therefore
/// emits a one-component sequence containing only the OID.
pub fn algorithm_identifier_der(parameter_set: ParameterSet) -> DilithiumResult<Vec<u8>> {
    algorithm_identifier(parameter_set)?
        .to_der()
        .map_err(|_| DilithiumError::MalformedPkix("failed to encode AlgorithmIdentifier"))
}

/// Decodes and validates an RFC 9881 ML-DSA `AlgorithmIdentifier`.
///
/// A DER `NULL` or any other parameter value is rejected. This is stricter than
/// generic SPKI helpers that sometimes normalize `NULL` and absent parameters:
/// RFC 9881 says the field "MUST be absent".
pub fn decode_algorithm_identifier(der: &[u8]) -> DilithiumResult<ParameterSet> {
    let algorithm = AlgorithmIdentifierRef::from_der(der)
        .map_err(|_| DilithiumError::MalformedPkix("malformed AlgorithmIdentifier DER"))?;
    validate_absent_parameters(&algorithm)?;
    parameter_set_for_oid(algorithm.oid)
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

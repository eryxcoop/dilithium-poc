//! RFC 9881 object identifiers for ML-DSA.

use der::asn1::ObjectIdentifier;

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ParameterSet, ParameterSetId};

/// RFC 9881 `id-ml-dsa-44`: `2.16.840.1.101.3.4.3.17`.
pub const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// RFC 9881 `id-ml-dsa-65`: `2.16.840.1.101.3.4.3.18`.
pub const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// RFC 9881 `id-ml-dsa-87`: `2.16.840.1.101.3.4.3.19`.
pub const ID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// Returns the RFC 9881 OID for a FIPS 204 ML-DSA parameter set.
pub fn oid_for_parameter_set(parameter_set: ParameterSet) -> DilithiumResult<ObjectIdentifier> {
    match parameter_set.id {
        ParameterSetId::MlDsa44 => Ok(ID_ML_DSA_44),
        ParameterSetId::MlDsa65 => Ok(ID_ML_DSA_65),
        ParameterSetId::MlDsa87 => Ok(ID_ML_DSA_87),
        #[cfg(any(test, feature = "experimental-params"))]
        ParameterSetId::Experimental => Err(DilithiumError::InvalidParameterSet),
    }
}

/// Returns the FIPS 204 parameter set identified by an RFC 9881 OID.
pub fn parameter_set_for_oid(oid: ObjectIdentifier) -> DilithiumResult<ParameterSet> {
    match oid {
        ID_ML_DSA_44 => Ok(ML_DSA_44),
        ID_ML_DSA_65 => Ok(ML_DSA_65),
        ID_ML_DSA_87 => Ok(ML_DSA_87),
        _ => Err(DilithiumError::InvalidParameterSet),
    }
}

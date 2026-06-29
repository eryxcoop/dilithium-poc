//! CMS digest algorithm policy and implementations.

use der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{ParameterSet, ParameterSetId};
use crate::xof::{shake128, shake256};

use crate::pkix::cms::oid::{
    ID_SHA3_256, ID_SHA3_384, ID_SHA3_512, ID_SHA256, ID_SHA384, ID_SHA512, ID_SHAKE128,
    ID_SHAKE256,
};

/// CMS digest algorithms allowed by RFC 9882 Table 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmsDigestAlgorithm {
    /// SHA-256, suitable for ML-DSA-44 signed attributes.
    Sha256,
    /// SHA-384, suitable for ML-DSA-44 and ML-DSA-65 signed attributes.
    Sha384,
    /// SHA-512, mandatory-to-support and suitable for every ML-DSA parameter set.
    Sha512,
    /// SHA3-256, suitable for ML-DSA-44 signed attributes.
    Sha3_256,
    /// SHA3-384, suitable for ML-DSA-44 and ML-DSA-65 signed attributes.
    Sha3_384,
    /// SHA3-512, suitable for every ML-DSA parameter set.
    Sha3_512,
    /// SHAKE128 as a CMS message digest, producing 256 bits.
    Shake128,
    /// SHAKE256 as a CMS message digest, producing 512 bits.
    Shake256,
}

impl CmsDigestAlgorithm {
    /// Returns whether RFC 9882 Table 1 permits this digest for `parameter_set`.
    pub fn is_suitable_for(self, parameter_set: ParameterSet) -> bool {
        match parameter_set.id {
            ParameterSetId::MlDsa44 => true,
            ParameterSetId::MlDsa65 => matches!(
                self,
                Self::Sha384 | Self::Sha512 | Self::Sha3_384 | Self::Sha3_512 | Self::Shake256
            ),
            ParameterSetId::MlDsa87 => {
                matches!(self, Self::Sha512 | Self::Sha3_512 | Self::Shake256)
            }
            #[cfg(any(test, feature = "experimental-params"))]
            ParameterSetId::Experimental => false,
        }
    }

    pub(crate) fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => ID_SHA256,
            Self::Sha384 => ID_SHA384,
            Self::Sha512 => ID_SHA512,
            Self::Sha3_256 => ID_SHA3_256,
            Self::Sha3_384 => ID_SHA3_384,
            Self::Sha3_512 => ID_SHA3_512,
            Self::Shake128 => ID_SHAKE128,
            Self::Shake256 => ID_SHAKE256,
        }
    }

    pub(crate) fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(input).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(input).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(input).to_vec(),
            Self::Shake128 => shake128(input, 32),
            Self::Shake256 => shake256(input, 64),
        }
    }

    pub(crate) fn from_oid(oid: ObjectIdentifier) -> DilithiumResult<Self> {
        match oid {
            ID_SHA256 => Ok(Self::Sha256),
            ID_SHA384 => Ok(Self::Sha384),
            ID_SHA512 => Ok(Self::Sha512),
            ID_SHA3_256 => Ok(Self::Sha3_256),
            ID_SHA3_384 => Ok(Self::Sha3_384),
            ID_SHA3_512 => Ok(Self::Sha3_512),
            ID_SHAKE128 => Ok(Self::Shake128),
            ID_SHAKE256 => Ok(Self::Shake256),
            _ => Err(DilithiumError::MalformedPkix(
                "unsupported CMS digest algorithm",
            )),
        }
    }

    pub(crate) fn require_suitable_for(self, parameter_set: ParameterSet) -> DilithiumResult<()> {
        if self.is_suitable_for(parameter_set) {
            Ok(())
        } else {
            Err(DilithiumError::MalformedPkix(
                "CMS digest algorithm is too weak for ML-DSA parameter set",
            ))
        }
    }
}

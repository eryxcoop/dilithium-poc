//! Complete FIPS 204 ML-DSA parameter-set descriptions.

use super::constants::Q;
use super::core::CoreParams;
use super::ids::ParameterSetId;
use super::sizes::EncodedSizes;

/// Static metadata for a FIPS 204 ML-DSA parameter set.
///
/// This type groups human-facing identifiers, cryptographic parameters, and
/// raw encoding sizes without flattening everything into one large field list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterSet {
    /// Stable enum identifier for the parameter set.
    pub id: ParameterSetId,
    /// Human-readable FIPS name, for example `"ML-DSA-44"`.
    pub name: &'static str,
    /// NIST PQC security category claimed by FIPS 204.
    pub security_category: u8,
    /// Core cryptographic parameters used by the algorithms.
    pub core: CoreParams,
    /// Raw FIPS 204 encoding sizes for keys and signatures.
    pub sizes: EncodedSizes,
}

/// FIPS 204 ML-DSA-44 parameter set.
pub const ML_DSA_44: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa44,
    name: "ML-DSA-44",
    security_category: 2,
    core: CoreParams {
        k: 4,
        l: 4,
        eta: 2,
        tau: 39,
        lambda: 128,
        gamma1: 1 << 17,
        gamma2: (Q - 1) / 88,
        beta: 78,
        omega: 80,
    },
    sizes: EncodedSizes {
        public_key_bytes: 1_312,
        private_key_bytes: 2_560,
        signature_bytes: 2_420,
    },
};

/// FIPS 204 ML-DSA-65 parameter set.
pub const ML_DSA_65: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa65,
    name: "ML-DSA-65",
    security_category: 3,
    core: CoreParams {
        k: 6,
        l: 5,
        eta: 4,
        tau: 49,
        lambda: 192,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        beta: 196,
        omega: 55,
    },
    sizes: EncodedSizes {
        public_key_bytes: 1_952,
        private_key_bytes: 4_032,
        signature_bytes: 3_309,
    },
};

/// FIPS 204 ML-DSA-87 parameter set.
pub const ML_DSA_87: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa87,
    name: "ML-DSA-87",
    security_category: 5,
    core: CoreParams {
        k: 8,
        l: 7,
        eta: 2,
        tau: 60,
        lambda: 256,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        beta: 120,
        omega: 75,
    },
    sizes: EncodedSizes {
        public_key_bytes: 2_592,
        private_key_bytes: 4_896,
        signature_bytes: 4_627,
    },
};

/// All FIPS 204 ML-DSA parameter sets supported by this POC.
pub const PARAMETER_SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

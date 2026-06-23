//! Complete FIPS 204 ML-DSA parameter-set descriptions.

use crate::params::constants::{D, Q};
use crate::params::core::CoreParams;
use crate::params::ids::ParameterSetId;
use crate::params::sizes::EncodedSizes;

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

impl ParameterSet {
    /// Returns the expected raw public-key size from the FIPS 204 formula.
    pub const fn derived_public_key_bytes(&self) -> usize {
        32 + (32 * self.core.k * (bit_length_u32(Q - 1) - D as usize))
    }

    /// Returns the expected raw expanded private-key size from the FIPS 204 formula.
    pub const fn derived_private_key_bytes(&self) -> usize {
        32 + 32
            + 64
            + (32
                * (((self.core.l + self.core.k) * bit_length_u32(2 * self.core.eta))
                    + ((D as usize) * self.core.k)))
    }

    /// Returns the expected raw signature size from the FIPS 204 formula.
    pub const fn derived_signature_bytes(&self) -> usize {
        (self.core.lambda as usize / 4)
            + (self.core.l * 32 * (1 + bit_length_u32(self.core.gamma1 - 1)))
            + (self.core.omega as usize)
            + self.core.k
    }

    /// Returns the length in bytes of `c_tilde` for signatures.
    ///
    /// FIPS 204 uses `lambda / 4`, giving 32, 48, and 64 bytes for
    /// ML-DSA-44, ML-DSA-65, and ML-DSA-87 respectively.
    pub const fn challenge_bytes(&self) -> usize {
        self.core.lambda as usize / 4
    }

    /// Returns the maximum encoded `w1` coefficient.
    ///
    /// FIPS 204 uses `(q - 1) / (2 * gamma2) - 1`, giving 43 for ML-DSA-44
    /// and 15 for ML-DSA-65/87.
    pub const fn w1_max(&self) -> u32 {
        (Q - 1) / (2 * self.core.gamma2) - 1
    }

    /// Returns `true` when the stored sizes match the formulas from FIPS 204.
    pub const fn has_consistent_sizes(&self) -> bool {
        self.sizes.public_key_bytes == self.derived_public_key_bytes()
            && self.sizes.private_key_bytes == self.derived_private_key_bytes()
            && self.sizes.signature_bytes == self.derived_signature_bytes()
    }

    /// Builds a non-standard parameter set for tests or experimental benches.
    #[cfg(any(test, feature = "experimental-params"))]
    pub const fn new_experimental(
        name: &'static str,
        security_category: u8,
        core: CoreParams,
        sizes: EncodedSizes,
    ) -> Self {
        Self {
            id: ParameterSetId::Experimental,
            name,
            security_category,
            core,
            sizes,
        }
    }
}

const fn bit_length_u32(value: u32) -> usize {
    let mut bits = 0usize;
    let mut n = value;
    while n != 0 {
        bits += 1;
        n >>= 1;
    }
    bits
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

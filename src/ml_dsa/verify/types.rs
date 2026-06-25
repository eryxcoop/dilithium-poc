//! Typed intermediate values used by FIPS 204 verification.

use crate::encoding::{EncodedPublicKeyParts, EncodedSignatureParts};
use crate::params::ParameterSet;
use crate::poly::{NttMatrix, Poly};

use super::super::sign::MessageRepresentative;

/// Prepared state consumed by `ML-DSA.Verify_internal`.
pub(super) struct VerificationState {
    /// ML-DSA parameter set for dimensions and bounds.
    pub(super) parameter_set: ParameterSet,
    /// Decoded public-key components `(ρ, t₁)`.
    pub(super) public_parts: EncodedPublicKeyParts,
    /// Decoded signature components `(c̃, z, h)`.
    pub(super) signature_parts: EncodedSignatureParts,
    /// Public matrix `Â = ExpandA(ρ)`.
    pub(super) a_hat: NttMatrix,
    /// Message representative `μ = H(tr || M′, 64)`.
    pub(super) mu: MessageRepresentative,
    /// Sparse challenge polynomial `c = SampleInBall(c̃)`.
    pub(super) c: Poly,
}

impl VerificationState {
    /// Builds the prepared state for the FIPS 204 verification equations.
    pub(super) fn new(
        parameter_set: ParameterSet,
        public_parts: EncodedPublicKeyParts,
        signature_parts: EncodedSignatureParts,
        a_hat: NttMatrix,
        mu: MessageRepresentative,
        c: Poly,
    ) -> Self {
        Self {
            parameter_set,
            public_parts,
            signature_parts,
            a_hat,
            mu,
            c,
        }
    }
}

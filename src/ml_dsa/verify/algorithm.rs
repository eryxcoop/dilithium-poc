//! External and internal ML-DSA verification steps.

use crate::encoding::{pk_decode, sig_decode};
use crate::error::DilithiumResult;
use crate::poly::PolyVector;
use crate::sampling::{ExpandASeed, expand_a, sample_in_ball};

use super::super::context::format_message;
use super::super::sign::{ChallengeSeed, MessageRepresentative};
use super::super::types::{PublicKey, Signature};
use super::types::VerificationState;

impl PublicKey {
    /// Verifies an ML-DSA signature for a byte-aligned message and context.
    ///
    /// The `context` argument is the FIPS 204 pure ML-DSA context string. It
    /// must match the context used during signing; a valid signature for one
    /// context does not verify under a different context. Pass `b""` for the
    /// default context, including RFC 9881 PKIX uses.
    ///
    /// This is the external FIPS 204 `ML-DSA.Verify` path for pure ML-DSA.
    /// Malformed public keys, malformed signatures, parameter-set mismatches,
    /// contexts longer than 255 bytes, and cryptographic mismatches are all
    /// reported as `false`.
    ///
    /// At a high level, this decodes `pk = pkEncode(ρ, t₁)` and
    /// `sig = sigEncode(c̃, z, h)`, recomputes `μ = H(H(pk, 64) || M′, 64)`,
    /// reconstructs `w₁′ = UseHint(h, Âz - c·t₁·2ᵈ)`, and accepts only when
    /// `c̃ == H(μ || w1Encode(w₁′), λ/4)` and `||z||∞ < γ₁ - β`.
    pub fn verify(&self, message: &[u8], signature: &Signature, context: &[u8]) -> bool {
        let parameter_set = self.parameter_set();

        // Verify that the external pure-ML-DSA context can be encoded as M′.
        let formatted_message = match format_message(message, context) {
            Ok(formatted_message) => formatted_message,
            Err(_) => return false,
        };

        // Verify that the signature belongs to the same ML-DSA parameter set.
        if signature.parameter_set() != parameter_set {
            return false;
        }

        // Verify the raw FIPS encodings: pkEncode(ρ, t₁) and sigEncode(c̃, z, h).
        let public_parts = match pk_decode(self.as_bytes(), parameter_set) {
            Ok(parts) => parts,
            Err(_) => return false,
        };
        let signature_parts = match sig_decode(signature.as_bytes(), parameter_set) {
            Ok(parts) => parts,
            Err(_) => return false,
        };

        // Recompute Â, tr, μ, and c from public data and the encoded challenge.
        let a_hat = match expand_a(ExpandASeed::new(public_parts.rho), parameter_set) {
            Ok(a_hat) => a_hat,
            Err(_) => return false,
        };
        let tr = self.hash();
        let mu = MessageRepresentative::derive(&tr, &formatted_message);
        let c = match sample_in_ball(&signature_parts.c_tilde, parameter_set) {
            Ok(c) => c,
            Err(_) => return false,
        };

        VerificationState::new(parameter_set, public_parts, signature_parts, a_hat, mu, c).run()
    }
}

impl VerificationState {
    /// Runs the prepared FIPS 204 verification equations.
    fn run(self) -> bool {
        // Reconstruct w′ = Âz - c·t₁·2ᵈ in the coefficient domain.
        let w_approx = match self.reconstruct_w_approx() {
            Ok(value) => value,
            Err(_) => return false,
        };

        // Verify that the hints recover the high bits committed by the signer.
        let w1_prime = match self.signature_parts.hints.use_on(&w_approx) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let c_tilde_prime = match ChallengeSeed::derive(&self.mu, &w1_prime, self.parameter_set) {
            Ok(value) => value,
            Err(_) => return false,
        };

        // Verify the final FIPS acceptance predicates for z and c̃.
        !self
            .signature_parts
            .z
            .infinity_norm_at_least(self.parameter_set.core.gamma1 - self.parameter_set.core.beta)
            && c_tilde_prime.as_bytes() == self.signature_parts.c_tilde.as_slice()
    }

    /// Reconstructs `w′ = Âz - c·t₁·2ᵈ` for FIPS 204 verification.
    fn reconstruct_w_approx(&self) -> DilithiumResult<PolyVector> {
        let z_hat = self.signature_parts.z.ntt()?;
        let a_z = self.a_hat.multiply_ntt_vector(&z_hat, self.parameter_set)?;
        let c_hat = self.c.ntt();
        let t1_times_2d = self.public_parts.t1.multiply_by_2_power_d()?;
        let t1_hat = t1_times_2d.ntt()?;
        let c_t1 = c_hat.multiply_ntt_vector(&t1_hat, self.parameter_set.core.k)?;
        a_z.checked_sub(&c_t1)
    }
}

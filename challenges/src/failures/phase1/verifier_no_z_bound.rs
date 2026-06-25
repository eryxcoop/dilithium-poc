//! `verifier_no_z_bound`: accepting oversized `z` leaves the short-vector domain.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};
use crate::toy::{ToyParams, ToyPoly};

/// Runs the missing-`z`-bound classroom demo.
pub fn run() -> ChallengeRun {
    let params = ToyParams::new(4, 257).expect("valid toy params");
    let z = ToyPoly::from_coeffs(params, vec![42, 0, 0, 0]).expect("valid z");
    let bound = 8;
    let strict_accepts = z.infinity_norm() < bound;
    let vulnerable_accepts = true;
    let success = vulnerable_accepts && !strict_accepts;

    let transcript = Transcript::new()
        .step(
            "Oversized response",
            format!(
                "The forged response has ||z||∞ = {}, while the toy bound is γ₁ - β = {bound}.",
                z.infinity_norm()
            ),
        )
        .step(
            "Vulnerable verifier",
            "The broken path checks the challenge relation but skips the short-vector predicate.",
        )
        .step(
            "FIPS defense",
            "ML-DSA accepts only if ||z||∞ < γ₁ - β; this keeps responses in the intended short domain.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "verifier_no_z_bound",
            "Verifier Without z Infinity-Norm Bound",
            ChallengeMode::ToyParams,
            "skips ||z||∞ < γ₁ - β",
        ),
        transcript,
        success,
    )
}

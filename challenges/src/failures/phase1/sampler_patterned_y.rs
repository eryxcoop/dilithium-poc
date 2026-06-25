//! `sampler_patterned_y`: patterned masks leak equations.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};
use crate::toy::{ToyParams, ToyPoly};

/// Runs the patterned-mask classroom demo.
pub fn run() -> ChallengeRun {
    let params = ToyParams::new(4, 97).expect("valid toy params");
    let secret = ToyPoly::from_coeffs(params, vec![3, -2, 1, 4]).expect("valid secret");
    let patterned_y = ToyPoly::from_coeffs(params, vec![5, 5, 5, 5]).expect("valid mask");
    let challenge = 1;
    let z = patterned_y
        .checked_add(&secret.scalar_mul(challenge))
        .expect("same toy ring");
    let recovered = z.checked_sub(&patterned_y).expect("same toy ring");
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            "The vulnerable sampler emits y = [5, 5, 5, 5], a visible repeated pattern.",
        )
        .step(
            "Leak",
            format!(
                "With c = {challenge}, the response is z = y + c·s₁, so z - y reveals {:?}.",
                recovered.centered_coeffs()
            ),
        )
        .step(
            "Why it still looks plausible",
            "A verifier that only checks the final equation can accept while the mask distribution leaks structure.",
        )
        .step(
            "FIPS defense",
            "ExpandMask(ρ″, κ) samples y from the full prescribed range; replacing it with a patterned sampler violates the signing distribution.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "sampler_patterned_y",
            "Patterned y Leaks Toy Equations",
            ChallengeMode::ToyParams,
            "replaces ExpandMask(ρ″, κ) with a patterned mask sampler",
        ),
        transcript,
        success,
    )
}

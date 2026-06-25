//! `verifier_no_ctilde`: skipping the challenge binding makes forgery trivial.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

/// Runs the missing-`c̃`-check classroom demo.
pub fn run() -> ChallengeRun {
    let supplied_ctilde = "attacker-chosen-c-tilde";
    let recomputed_ctilde = "H(μ || w1Encode(w₁′))";
    let strict_accepts = supplied_ctilde == recomputed_ctilde;
    let vulnerable_accepts = true;
    let success = vulnerable_accepts && !strict_accepts;

    let transcript = Transcript::new()
        .step(
            "Forgery",
            "The attacker chooses structurally convenient z and h, then writes any c̃ into the signature.",
        )
        .step(
            "Vulnerable verifier",
            "The broken path reconstructs w₁′ but never checks c̃ == H(μ || w1Encode(w₁′)).",
        )
        .step(
            "Strict comparison",
            format!(
                "FIPS recomputes c̃′ = {recomputed_ctilde}; supplied c̃ = {supplied_ctilde}; strict_accepts = {strict_accepts}."
            ),
        )
        .step(
            "FIPS defense",
            "The final c̃ comparison binds the Fiat-Shamir challenge to μ and w₁′.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "verifier_no_ctilde",
            "Verifier Without c̃ Binding",
            ChallengeMode::ToyParams,
            "skips c̃ == H(μ || w1Encode(w₁′))",
        ),
        transcript,
        success,
    )
}

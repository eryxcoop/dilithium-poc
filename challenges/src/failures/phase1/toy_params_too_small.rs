//! `toy_params_too_small`: tiny rings make exhaustive recovery visible.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

/// Runs the too-small-parameter classroom demo.
pub fn run() -> ChallengeRun {
    let q = 17;
    let a = 5;
    let secret = 6;
    let public = (a * secret) % q;
    let recovered = (0..q)
        .find(|candidate| (a * candidate) % q == public)
        .expect("small field equation has a solution");
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Toy public equation",
            format!("With n = k = l = 1 and q = {q}, the public equation is t = a·s₁ = {public}."),
        )
        .step(
            "Exhaustive search",
            format!("Trying all {q} candidates recovers s₁ = {recovered}."),
        )
        .step(
            "FIPS defense",
            "ML-DSA parameter sets use large rings, coupled dimensions, τ, λ, γ₁, β, and ω so this classroom search is infeasible.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "toy_params_too_small",
            "Toy Parameters Too Small",
            ChallengeMode::ToyParams,
            "shrinks n, k, l, q, and the search space outside FIPS 204",
        ),
        transcript,
        success,
    )
}

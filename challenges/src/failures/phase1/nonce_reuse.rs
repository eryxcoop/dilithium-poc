//! `nonce_reuse`: recover a toy secret from two signatures with the same `y`.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

const MODULUS: i64 = 97;

/// Runs the nonce-reuse classroom demo.
pub fn run() -> ChallengeRun {
    let secret = 23;
    let reused_y = 41;
    let c1 = 7;
    let c2 = 31;
    let z1 = reduce(reused_y + c1 * secret);
    let z2 = reduce(reused_y + c2 * secret);
    let recovered = reduce((z2 - z1) * inverse_mod(c2 - c1, MODULUS));
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy signer uses q = {MODULUS}, secret s₁ = {secret}, and accidentally reuses y = {reused_y}."
            ),
        )
        .step(
            "Two signatures",
            format!("The vulnerable equations are z₁ = y + c₁s₁ = {z1} and z₂ = y + c₂s₁ = {z2}."),
        )
        .step(
            "Exploit",
            format!(
                "Subtracting cancels y: s₁ = (z₂ - z₁)/(c₂ - c₁) = {recovered} mod {MODULUS}."
            ),
        )
        .step(
            "FIPS defense",
            "ML-DSA derives each mask from ρ″ and κ; rejected attempts advance κ, so two accepted signatures must not reuse the same y.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "nonce_reuse",
            "Nonce Reuse Recovers The Toy Secret",
            ChallengeMode::ToyParams,
            "reuses the same y / ρ″,κ across signatures",
        ),
        transcript,
        success,
    )
}

fn reduce(value: i64) -> i64 {
    value.rem_euclid(MODULUS)
}

fn inverse_mod(value: i64, modulus: i64) -> i64 {
    (1..modulus)
        .find(|candidate| (value * candidate).rem_euclid(modulus) == 1)
        .expect("demo chooses an invertible value")
}

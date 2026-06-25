//! `verifier_no_omega`: accepting dense hints gives the adversary too much help.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

/// Runs the missing-`ω`-bound classroom demo.
pub fn run() -> ChallengeRun {
    let omega = 2usize;
    let hint_weight = 7usize;
    let strict_accepts = hint_weight <= omega;
    let vulnerable_accepts = true;
    let success = vulnerable_accepts && !strict_accepts;

    let transcript = Transcript::new()
        .step(
            "Dense hints",
            format!("The attacker supplies h with weight {hint_weight}, but toy ω = {omega}."),
        )
        .step(
            "Vulnerable verifier",
            "The broken path treats h as harmless metadata and applies it without enforcing the weight/canonical encoding.",
        )
        .step(
            "FIPS defense",
            "sigDecode and UseHint must reject malformed or over-ω hints because h is adversarial input.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "verifier_no_omega",
            "Verifier Accepts Dense Hints",
            ChallengeMode::ToyParams,
            "accepts hint vectors with weight greater than ω",
        ),
        transcript,
        success,
    )
}

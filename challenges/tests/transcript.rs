use dilithium_poc_challenges::shared::{
    ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript,
};

#[cfg(not(feature = "failure-challenges"))]
#[test]
fn feature_gate_is_disabled_by_default() {
    assert!(!dilithium_poc_challenges::failure_challenges_enabled());
}

#[test]
fn transcript_rendering_is_stable_and_classroom_friendly() {
    let metadata = ChallengeMetadata::new(
        "verifier_no_ctilde",
        "Verifier Without c̃ Binding",
        ChallengeMode::ToyParams,
        "skips c̃ == H(μ || w1Encode(w1′))",
    );
    let transcript = Transcript::new()
        .step("Bug", "The vulnerable verifier accepts attacker-chosen c̃.")
        .step("FIPS defense", "The strict verifier recomputes c̃.");

    let run = ChallengeRun::new(metadata, transcript, true);
    let rendered = run.render();

    assert!(run.success());
    assert!(rendered.contains("# Verifier Without c̃ Binding"));
    assert!(rendered.contains("mode: toy params"));
    assert!(rendered.contains("result: success"));
}

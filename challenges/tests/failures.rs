#![cfg(feature = "failure-challenges")]

use dilithium_poc_challenges::failures::{
    challenge_runs, challenges_success, eta_unbounded_secret, gamma1_beta_boundary_oracle,
    lambda_too_short_cross_message, nonce_reuse, sampler_patterned_y, toy_dense_hint_forgery,
    toy_params_too_small, verifier_no_ctilde,
};

#[test]
fn challenge_runs_are_available_in_catalog_order() {
    let runs = challenge_runs();
    let ids = runs.iter().map(|run| run.metadata().id).collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec![
            "nonce_reuse",
            "sampler_patterned_y",
            "eta_unbounded_secret",
            "gamma1_beta_boundary_oracle",
            "verifier_no_ctilde",
            "lambda_too_short_cross_message",
            "toy_dense_hint_forgery",
            "toy_params_too_small",
        ]
    );
    assert!(challenges_success());
}

#[test]
fn challenge_transcripts_explain_bug_and_defense() {
    for run in [
        nonce_reuse(),
        sampler_patterned_y(),
        eta_unbounded_secret(),
        gamma1_beta_boundary_oracle(),
        verifier_no_ctilde(),
        lambda_too_short_cross_message(),
        toy_dense_hint_forgery(),
        toy_params_too_small(),
    ] {
        let rendered = run.render();
        assert!(
            run.success(),
            "{} should demonstrate the failure",
            run.metadata().id
        );
        assert!(rendered.contains("broken rule:"));
        assert!(rendered.contains("FIPS defense"));
        assert!(rendered.contains("result: success"));
    }
}

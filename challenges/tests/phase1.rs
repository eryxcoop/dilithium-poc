#![cfg(feature = "failure-challenges")]

use dilithium_poc_challenges::failures::phase1::{
    nonce_reuse, phase1_runs, phase1_success, sampler_patterned_y, toy_dense_hint_forgery,
    toy_params_too_small, verifier_no_ctilde, verifier_no_z_bound,
};

#[test]
fn phase1_runs_are_available_in_roadmap_order() {
    let runs = phase1_runs();
    let ids = runs.iter().map(|run| run.metadata().id).collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec![
            "nonce_reuse",
            "sampler_patterned_y",
            "verifier_no_ctilde",
            "verifier_no_z_bound",
            "toy_dense_hint_forgery",
            "toy_params_too_small",
        ]
    );
    assert!(phase1_success());
}

#[test]
fn phase1_transcripts_explain_bug_and_defense() {
    for run in [
        nonce_reuse(),
        sampler_patterned_y(),
        verifier_no_ctilde(),
        verifier_no_z_bound(),
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

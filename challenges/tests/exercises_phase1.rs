#![cfg(feature = "exercises")]

use dilithium_poc_challenges::exercises::phase1::{
    recover_secret_from_patterned_mask, recover_secret_from_reused_mask,
    recover_toy_secret_by_search, strict_ctilde_accepts, strict_hint_weight_accepts,
    strict_z_bound_accepts,
};

#[test]
fn nonce_reuse_exercise_recovers_secret() {
    assert_eq!(recover_secret_from_reused_mask(8, 75, 7, 31, 97), 23);
}

#[test]
fn patterned_y_exercise_recovers_secret_coefficients() {
    assert_eq!(
        recover_secret_from_patterned_mask(&[8, 3, 6, 9], &[5, 5, 5, 5], 97),
        vec![3, 95, 1, 4]
    );
}

#[test]
fn verifier_no_ctilde_exercise_rejects_mismatch() {
    assert!(strict_ctilde_accepts("same", "same"));
    assert!(!strict_ctilde_accepts("attacker", "recomputed"));
}

#[test]
fn verifier_no_z_bound_exercise_rejects_oversized_z() {
    assert!(strict_z_bound_accepts(7, 8));
    assert!(!strict_z_bound_accepts(8, 8));
    assert!(!strict_z_bound_accepts(42, 8));
}

#[test]
fn verifier_no_omega_exercise_rejects_dense_hints() {
    assert!(strict_hint_weight_accepts(2, 2));
    assert!(!strict_hint_weight_accepts(7, 2));
}

#[test]
fn toy_params_too_small_exercise_recovers_by_search() {
    assert_eq!(recover_toy_secret_by_search(5, 13, 17), Some(6));
    assert_eq!(recover_toy_secret_by_search(0, 1, 17), None);
}

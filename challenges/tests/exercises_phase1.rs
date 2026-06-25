#![cfg(feature = "exercises")]

use dilithium_poc_challenges::exercises::phase1::{
    estimate_secret_from_biased_masks, recover_secret_from_reused_mask,
    recover_toy_secret_by_search, strict_ctilde_accepts, strict_hint_weight_accepts,
    strict_z_bound_accepts,
};

#[test]
fn nonce_reuse_exercise_recovers_secret() {
    assert_eq!(recover_secret_from_reused_mask(8, 75, 7, 31, 97), 23);
}

#[test]
fn biased_y_exercise_estimates_secret_coefficients() {
    let (secret, sums, counts, bias_means) = biased_mask_observations();

    assert_eq!(
        estimate_secret_from_biased_masks(&sums, &counts, &bias_means, 4),
        secret
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

fn biased_mask_observations() -> (Vec<i64>, Vec<i64>, Vec<usize>, Vec<f64>) {
    const ETA: i64 = 4;
    const L: usize = 5;
    const N: usize = 256;
    const SECRET_COEFFICIENTS: usize = L * N;
    const SAMPLES: usize = 512;
    const POSITIVE_BIAS_VALUES: [i64; 4] = [-1, 1, 3, 5];
    const NEGATIVE_BIAS_VALUES: [i64; 4] = [-5, -3, -1, 1];

    let secret = (0..SECRET_COEFFICIENTS)
        .map(|index| (index as i64 * 5 + 8).rem_euclid(2 * ETA + 1) - ETA)
        .collect::<Vec<_>>();
    let mut sums = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts = vec![0usize; SECRET_COEFFICIENTS];
    let bias_means = (0..SECRET_COEFFICIENTS)
        .map(|index| if index.is_multiple_of(2) { 2.0 } else { -2.0 })
        .collect::<Vec<_>>();

    for sample in 0..SAMPLES {
        for index in 0..secret.len() {
            let challenge = if sample % 8 < 4 { 1 } else { 0 };
            let values = if index.is_multiple_of(2) {
                POSITIVE_BIAS_VALUES
            } else {
                NEGATIVE_BIAS_VALUES
            };
            let y = values[(sample + index * 7) % values.len()];
            let z = y + challenge * secret[index];

            if challenge == 1 {
                sums[index] += z;
                counts[index] += 1;
            }
        }
    }

    (secret, sums, counts, bias_means)
}

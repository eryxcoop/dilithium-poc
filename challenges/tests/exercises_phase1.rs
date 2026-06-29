#![cfg(feature = "exercises")]

use dilithium_poc::ml_dsa::KeyPair;
use dilithium_poc::params::ML_DSA_44;
use dilithium_poc_challenges::exercises::phase1::{
    estimate_mask_bias_means, estimate_secret_from_biased_masks,
    forge_signature_without_ctilde_binding, recover_secret_from_reused_mask,
    recover_toy_secret_by_search,
};

#[test]
fn nonce_reuse_exercise_recovers_secret() {
    assert_eq!(recover_secret_from_reused_mask(8, 75, 7, 31, 97), 23);
}

#[test]
fn biased_y_exercise_estimates_secret_coefficients() {
    let (secret, mask_samples, sums, counts) = biased_mask_observations();
    let bias_means = estimate_mask_bias_means(&mask_samples, secret.len());

    assert!(bias_means[0] > 1.5);
    assert!(bias_means[1] < -1.5);

    assert_eq!(
        estimate_secret_from_biased_masks(&sums, &counts, &bias_means, 4),
        secret
    );
}

#[test]
fn verifier_no_ctilde_exercise_forges_chosen_message_signature() {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, [0x44; 32]).unwrap();
    let message = b"forged message";
    let context = b"phase1";
    let signature = forge_signature_without_ctilde_binding(key_pair.public_key(), message, context);

    assert!(!key_pair.public_key().verify(message, &signature, context));
}

#[test]
fn toy_params_too_small_exercise_recovers_by_search() {
    assert_eq!(recover_toy_secret_by_search(5, 13, 17), Some(6));
    assert_eq!(recover_toy_secret_by_search(0, 1, 17), None);
}

fn biased_mask_observations() -> (Vec<i64>, Vec<Vec<i64>>, Vec<i64>, Vec<usize>) {
    const ETA: i64 = 4;
    const L: usize = 5;
    const N: usize = 256;
    const SECRET_COEFFICIENTS: usize = L * N;
    const AUDIT_SAMPLES: usize = 2_048;
    const SIGNATURE_SAMPLES: usize = 1_024;

    let secret = (0..SECRET_COEFFICIENTS)
        .map(|index| (index as i64 * 5 + 8).rem_euclid(2 * ETA + 1) - ETA)
        .collect::<Vec<_>>();
    let mut rng = ExerciseSplitMix64::new(0x5eed_5eed_d15a_b1a5);
    let mask_samples = (0..AUDIT_SAMPLES)
        .map(|_| {
            (0..SECRET_COEFFICIENTS)
                .map(|index| exercise_biased_mask(&mut rng, index))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut sums = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts = vec![0usize; SECRET_COEFFICIENTS];

    for _ in 0..SIGNATURE_SAMPLES {
        for index in 0..secret.len() {
            let challenge = rng.bit() as i64;
            let y = exercise_biased_mask(&mut rng, index);
            let z = y + challenge * secret[index];

            if challenge == 1 {
                sums[index] += z;
                counts[index] += 1;
            }
        }
    }

    (secret, mask_samples, sums, counts)
}

fn exercise_biased_mask(rng: &mut ExerciseSplitMix64, index: usize) -> i64 {
    let roll = rng.range(10);
    match (index.is_multiple_of(2), roll) {
        (true, 0..=4) => 4,
        (true, 5..=6) => 2,
        (true, 7) => 0,
        (true, 8) => -2,
        (true, _) => -4,
        (false, 0..=4) => -4,
        (false, 5..=6) => -2,
        (false, 7) => 0,
        (false, 8) => 2,
        (false, _) => 4,
    }
}

struct ExerciseSplitMix64 {
    state: u64,
}

impl ExerciseSplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn range(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }

    fn bit(&mut self) -> u8 {
        (self.next() >> 63) as u8
    }
}

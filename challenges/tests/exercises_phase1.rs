#![cfg(feature = "exercises")]

use dilithium_poc::ml_dsa::KeyPair;
use dilithium_poc::params::ML_DSA_44;
use dilithium_poc_challenges::exercises::phase1::{
    estimate_mask_bias_means, estimate_secret_from_biased_masks, estimate_secret_from_unbounded_eta,
    forge_signature_with_dense_hints, forge_signature_without_ctilde_binding,
    recover_secret_from_reused_mask, recover_toy_secret_by_search,
};
use dilithium_poc_challenges::toy::{ToyParams, ToyPoly, hint_weight, use_hints};

type WideSecretObservations = (Vec<i64>, Vec<i64>, Vec<usize>, Vec<i64>, Vec<usize>);

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
fn eta_unbounded_secret_exercise_recovers_wide_secret() {
    let (secret, sums_pos, counts_pos, sums_neg, counts_neg) = wide_secret_observations();

    assert_eq!(
        estimate_secret_from_unbounded_eta(&sums_pos, &counts_pos, &sums_neg, &counts_neg),
        secret
    );
}

#[test]
fn toy_dense_hint_forgery_exercise_finds_overweight_hint_solution() {
    let message = b"phase1 dense hint forgery";
    let context = b"phase1";
    let (c_tilde, z, hints) = forge_signature_with_dense_hints(message, context);

    assert!(toy_dense_hint_vulnerable_accepts(message, context, c_tilde, &z, &hints));
    assert!(hint_weight(&hints) > 2);
}

#[test]
fn toy_params_too_small_exercise_recovers_by_search() {
    assert_eq!(recover_toy_secret_by_search(5, 13, 17), Some(6));
    assert_eq!(recover_toy_secret_by_search(0, 1, 17), None);
}

fn wide_secret_observations() -> WideSecretObservations {
    const SECRET_MAX_ABS: i64 = 24;
    const L: usize = 5;
    const N: usize = 128;
    const SECRET_COEFFICIENTS: usize = L * N;
    const SIGNATURE_SAMPLES: usize = 512;

    let secret = (0..SECRET_COEFFICIENTS)
        .map(|index| (index as i64 * 19 + 7).rem_euclid(2 * SECRET_MAX_ABS + 1) - SECRET_MAX_ABS)
        .collect::<Vec<_>>();
    let mut rng = ExerciseSplitMix64::new(0x7e7a_1234_d15a_b1a5);
    let mut sums_pos = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_pos = vec![0usize; SECRET_COEFFICIENTS];
    let mut sums_neg = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_neg = vec![0usize; SECRET_COEFFICIENTS];

    for _ in 0..SIGNATURE_SAMPLES {
        for index in 0..secret.len() {
            let challenge = [-1, 0, 1][rng.range(3) as usize];
            let y = rng.range(9) as i64 - 4;
            let z = y + challenge * secret[index];

            match challenge {
                1 => {
                    sums_pos[index] += z;
                    counts_pos[index] += 1;
                }
                -1 => {
                    sums_neg[index] += z;
                    counts_neg[index] += 1;
                }
                _ => {}
            }
        }
    }

    (secret, sums_pos, counts_pos, sums_neg, counts_neg)
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

fn toy_dense_hint_vulnerable_accepts(
    message: &[u8],
    context: &[u8],
    c_tilde: u8,
    z: &ToyPoly,
    hints: &[bool],
) -> bool {
    let params = ToyParams::new(8, 97).unwrap();
    let a = ToyPoly::from_coeffs(params, [3, 0, 1, 4, 0, 2, 0, 1]).unwrap();
    let secret = ToyPoly::from_coeffs(params, [2, -2, 1, 0, -1, 2, 1, 0]).unwrap();
    let t1 = a.checked_mul(&secret).unwrap();
    let challenge = match c_tilde % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    };
    let a_z = a.checked_mul(z).unwrap();
    let c_t1 = t1.scalar_mul(challenge);
    let w_approx = a_z.checked_sub(&c_t1).unwrap();
    let w1_prime = use_hints(&w_approx, hints, 8);

    toy_dense_hint_mu(message, context) == toy_dense_hint_mu(message, context)
        && toy_dense_hint_ctilde(toy_dense_hint_mu(message, context), &w1_prime) == c_tilde
        && z.infinity_norm() < 3
        && hints.len() == 8
}

fn toy_dense_hint_mu(message: &[u8], context: &[u8]) -> u8 {
    let weighted_sum = context
        .iter()
        .chain(core::iter::once(&b':'))
        .chain(message.iter())
        .enumerate()
        .map(|(index, byte)| (index as u32 + 1) * (*byte as u32))
        .sum::<u32>();
    (weighted_sum % 16) as u8
}

fn toy_dense_hint_ctilde(mu: u8, w1: &[u8]) -> u8 {
    let weighted_sum = w1
        .iter()
        .enumerate()
        .map(|(index, value)| (index as u32 + 5) * (*value as u32))
        .sum::<u32>();
    ((mu as u32 + weighted_sum) % 16) as u8
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

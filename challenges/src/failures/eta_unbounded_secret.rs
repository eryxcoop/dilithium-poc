//! `eta_unbounded_secret`: wide secret coefficients leak through `z`.

use crate::shared::{
    rounded_prefix, ChallengeMetadata, ChallengeMode, ChallengeRun, SplitMix64, Transcript,
};

const ETA: i64 = 2;
const SECRET_MAX_ABS: i64 = 24;
const L: usize = 5;
const N: usize = 128;
const SECRET_COEFFICIENTS: usize = L * N;
const SIGNATURE_SAMPLES: usize = 512;
const PRNG_SEED: u64 = 0x7e7a_1234_d15a_b1a5;

/// Runs the wide-secret classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let mut rng = SplitMix64::new(PRNG_SEED);
    let mut sums_when_challenge_one = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_when_challenge_one = vec![0usize; SECRET_COEFFICIENTS];
    let mut sums_when_challenge_minus_one = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_when_challenge_minus_one = vec![0usize; SECRET_COEFFICIENTS];

    for _ in 0..SIGNATURE_SAMPLES {
        for index in 0..SECRET_COEFFICIENTS {
            let challenge = sampled_challenge(&mut rng);
            let y = centered_mask(&mut rng);
            let z = y + challenge * secret[index];

            match challenge {
                1 => {
                    sums_when_challenge_one[index] += z;
                    counts_when_challenge_one[index] += 1;
                }
                -1 => {
                    sums_when_challenge_minus_one[index] += z;
                    counts_when_challenge_minus_one[index] += 1;
                }
                _ => {}
            }
        }
    }

    let recovered = estimate_secret(
        &sums_when_challenge_one,
        &counts_when_challenge_one,
        &sums_when_challenge_minus_one,
        &counts_when_challenge_minus_one,
    );
    let estimator_prefix = estimate_secret_f64(
        &sums_when_challenge_one,
        &counts_when_challenge_one,
        &sums_when_challenge_minus_one,
        &counts_when_challenge_minus_one,
    );
    let min_positive_count = counts_when_challenge_one
        .iter()
        .copied()
        .min()
        .expect("there is at least one coefficient");
    let min_negative_count = counts_when_challenge_minus_one
        .iter()
        .copied()
        .min()
        .expect("there is at least one coefficient");
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy signer keeps a near-real secret shape with l = {L}, n = {N}, so there are {SECRET_COEFFICIENTS} coefficients. FIPS would require s₁ coefficients in [-eta, eta] with eta = {ETA}, but the broken path samples them in [-{SECRET_MAX_ABS}, {SECRET_MAX_ABS}]."
            ),
        )
        .step(
            "Observation model",
            "Each coefficient is emitted through zᵢ = yᵢ + cᵢ·s₁ᵢ, where yᵢ is centered noise in [-4, 4] and the toy challenge coordinate cᵢ is sampled from {-1, 0, 1}.",
        )
        .step(
            "Estimator",
            format!(
                "From {SIGNATURE_SAMPLES} signatures, every coefficient gets at least {min_positive_count} samples with cᵢ = 1 and {min_negative_count} with cᵢ = -1. Using E[zᵢ | cᵢ = 1] - E[zᵢ | cᵢ = -1] ≈ 2·s₁ᵢ gives first eight estimates {:?}.",
                rounded_prefix(&estimator_prefix, 8)
            ),
        )
        .step(
            "Recovery",
            format!(
                "Rounding the estimator recovers all {SECRET_COEFFICIENTS} coefficients exactly; the first eight recovered values are {:?}.",
                &recovered[..8]
            ),
        )
        .step(
            "FIPS defense",
            "ExpandS and secret-key decoding must keep s₁ and s₂ coefficients inside [-eta, eta]; otherwise c·s₁ dominates the mask and z leaks the secret statistically.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "eta_unbounded_secret",
            "Wide Secret Coefficients Leak Through z",
            ChallengeMode::ToyParams,
            "samples or accepts secret coefficients outside the |eta| bound",
        ),
        transcript,
        success,
    )
}

fn sampled_challenge(rng: &mut SplitMix64) -> i64 {
    match rng.range(3) {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

fn centered_mask(rng: &mut SplitMix64) -> i64 {
    rng.range(9) as i64 - 4
}

fn secret_coefficients() -> Vec<i64> {
    (0..SECRET_COEFFICIENTS)
        .map(|index| (index as i64 * 19 + 7).rem_euclid(2 * SECRET_MAX_ABS + 1) - SECRET_MAX_ABS)
        .collect()
}

fn estimate_secret(
    sums_when_challenge_one: &[i64],
    counts_when_challenge_one: &[usize],
    sums_when_challenge_minus_one: &[i64],
    counts_when_challenge_minus_one: &[usize],
) -> Vec<i64> {
    estimate_secret_f64(
        sums_when_challenge_one,
        counts_when_challenge_one,
        sums_when_challenge_minus_one,
        counts_when_challenge_minus_one,
    )
    .into_iter()
    .map(|estimate| estimate.round() as i64)
    .collect()
}

fn estimate_secret_f64(
    sums_when_challenge_one: &[i64],
    counts_when_challenge_one: &[usize],
    sums_when_challenge_minus_one: &[i64],
    counts_when_challenge_minus_one: &[usize],
) -> Vec<f64> {
    sums_when_challenge_one
        .iter()
        .zip(counts_when_challenge_one.iter())
        .zip(
            sums_when_challenge_minus_one
                .iter()
                .zip(counts_when_challenge_minus_one.iter()),
        )
        .map(|((&sum_pos, &count_pos), (&sum_neg, &count_neg))| {
            let mean_pos = sum_pos as f64 / count_pos as f64;
            let mean_neg = sum_neg as f64 / count_neg as f64;
            (mean_pos - mean_neg) / 2.0
        })
        .collect()
}

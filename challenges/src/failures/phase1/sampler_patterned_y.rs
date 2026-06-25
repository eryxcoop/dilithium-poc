//! `sampler_patterned_y`: biased masks leak statistically.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

const ETA: i64 = 4;
const L: usize = 5;
const N: usize = 256;
const SECRET_COEFFICIENTS: usize = L * N;
const SAMPLES: usize = 512;
const POSITIVE_BIAS_VALUES: [i64; 4] = [-1, 1, 3, 5];
const NEGATIVE_BIAS_VALUES: [i64; 4] = [-5, -3, -1, 1];

/// Runs the biased-mask classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let bias_means = bias_means();
    let mut sums_when_challenge_one = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_when_challenge_one = vec![0usize; SECRET_COEFFICIENTS];

    for sample in 0..SAMPLES {
        for index in 0..secret.len() {
            let challenge = challenge_bit(sample, index);
            let y = biased_mask(sample, index);
            let z = y + challenge * secret[index];

            if challenge == 1 {
                sums_when_challenge_one[index] += z;
                counts_when_challenge_one[index] += 1;
            }
        }
    }

    let recovered = estimate_secret(
        &sums_when_challenge_one,
        &counts_when_challenge_one,
        &bias_means,
        ETA,
    );
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy signer keeps the ML-DSA-65 shape for s₁: l = {L}, n = {N}, η = {ETA}, so there are {SECRET_COEFFICIENTS} secret coefficients and {SAMPLES} signatures."
            ),
        )
        .step(
            "Biased sampler",
            "The broken y sampler has position-dependent means: even flattened coefficients have E[yᵢ] = +2 and odd flattened coefficients have E[yᵢ] = -2.",
        )
        .step(
            "Estimator",
            format!(
                "Conditioning on cᵢ = 1 gives E[zᵢ] ≈ E[yᵢ] + s₁ᵢ. Subtracting the known bias recovers all {SECRET_COEFFICIENTS} coefficients; first eight are {:?}.",
                &recovered[..8]
            ),
        )
        .step(
            "FIPS defense",
            "ExpandMask(ρ″, κ) must not introduce position-dependent mean bias; otherwise many valid-looking signatures can leak s₁ statistically.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "sampler_patterned_y",
            "Biased y Leaks Toy Secrets Statistically",
            ChallengeMode::ToyParams,
            "replaces ExpandMask(ρ″, κ) with a position-biased mask sampler",
        ),
        transcript,
        success,
    )
}

fn challenge_bit(sample: usize, index: usize) -> i64 {
    let _ = index;
    if sample % 8 < 4 { 1 } else { 0 }
}

fn biased_mask(sample: usize, index: usize) -> i64 {
    let values = if index.is_multiple_of(2) {
        POSITIVE_BIAS_VALUES
    } else {
        NEGATIVE_BIAS_VALUES
    };
    values[(sample + index * 7) % values.len()]
}

fn estimate_secret(
    sums_when_challenge_one: &[i64],
    counts_when_challenge_one: &[usize],
    bias_means: &[f64],
    eta: i64,
) -> Vec<i64> {
    sums_when_challenge_one
        .iter()
        .zip(counts_when_challenge_one.iter())
        .zip(bias_means.iter())
        .map(|((&sum, &count), &bias_mean)| {
            let mean_z = sum as f64 / count as f64;
            (mean_z - bias_mean).round().clamp(-eta as f64, eta as f64) as i64
        })
        .collect()
}

fn secret_coefficients() -> Vec<i64> {
    (0..SECRET_COEFFICIENTS)
        .map(|index| (index as i64 * 5 + 8).rem_euclid(2 * ETA + 1) - ETA)
        .collect()
}

fn bias_means() -> Vec<f64> {
    (0..SECRET_COEFFICIENTS)
        .map(|index| if index.is_multiple_of(2) { 2.0 } else { -2.0 })
        .collect()
}

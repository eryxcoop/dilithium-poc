//! `sampler_patterned_y`: biased masks leak statistically.

use crate::shared::{
    rounded_prefix, ChallengeMetadata, ChallengeMode, ChallengeRun, SplitMix64, Transcript,
};

const ETA: i64 = 4;
const L: usize = 5;
const N: usize = 256;
const SECRET_COEFFICIENTS: usize = L * N;
const AUDIT_SAMPLES: usize = 2_048;
const SIGNATURE_SAMPLES: usize = 1_024;
const PRNG_SEED: u64 = 0x5eed_5eed_d15a_b1a5;

/// Runs the biased-mask classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let mut rng = SplitMix64::new(PRNG_SEED);
    let audit_samples = generate_mask_audit_samples(&mut rng);
    let estimated_bias_means = estimate_bias_means(&audit_samples, SECRET_COEFFICIENTS);
    let mut sums_when_challenge_one = vec![0i64; SECRET_COEFFICIENTS];
    let mut counts_when_challenge_one = vec![0usize; SECRET_COEFFICIENTS];

    for _ in 0..SIGNATURE_SAMPLES {
        for index in 0..secret.len() {
            let challenge = rng.bit() as i64;
            let y = biased_mask(&mut rng, index);
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
        &estimated_bias_means,
        ETA,
    );
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy signer keeps the ML-DSA-65 shape for s₁: l = {L}, n = {N}, η = {ETA}, so there are {SECRET_COEFFICIENTS} secret coefficients."
            ),
        )
        .step(
            "Sampler audit",
            format!(
                "The attacker samples {AUDIT_SAMPLES} y vectors and estimates mean(yᵢ). First six estimated means are {:?}.",
                rounded_prefix(&estimated_bias_means, 6)
            ),
        )
        .step(
            "Estimator",
            format!(
                "From {SIGNATURE_SAMPLES} signatures, conditioning on cᵢ = 1 gives E[zᵢ] ≈ E[yᵢ] + s₁ᵢ. Subtracting the inferred bias recovers all {SECRET_COEFFICIENTS} coefficients; first eight are {:?}.",
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

fn biased_mask(rng: &mut SplitMix64, index: usize) -> i64 {
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

fn generate_mask_audit_samples(rng: &mut SplitMix64) -> Vec<Vec<i64>> {
    (0..AUDIT_SAMPLES)
        .map(|_| {
            (0..SECRET_COEFFICIENTS)
                .map(|index| biased_mask(rng, index))
                .collect()
        })
        .collect()
}

fn estimate_bias_means(mask_samples: &[Vec<i64>], coefficient_count: usize) -> Vec<f64> {
    let mut sums = vec![0i64; coefficient_count];
    for sample in mask_samples {
        for (index, &value) in sample.iter().enumerate() {
            sums[index] += value;
        }
    }

    sums.into_iter()
        .map(|sum| sum as f64 / mask_samples.len() as f64)
        .collect()
}

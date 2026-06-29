//! `gamma2_lowbits_boundary_oracle`: low-bit boundary signatures reveal `s2`.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, SplitMix64, Transcript};

const ETA: i64 = 2;
const DEGREE: usize = 6;
const TAU: usize = 3;
const GAMMA2: i64 = 16;
const BETA: i64 = (TAU as i64) * ETA;
const EDGE_OBSERVATIONS: usize = 128;
const PRNG_SEED: u64 = 0x0006_2b17_0f00_d123;

/// Runs the gamma2/beta low-bits boundary-oracle classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let observations = collect_lowbits_observations(&secret, EDGE_OBSERVATIONS);
    let recovered = recover_secret_from_lowbits_oracle(&observations, ETA);
    let edge_count = observations
        .iter()
        .map(|observation| {
            observation
                .edge_r0
                .iter()
                .filter(|edge| edge.is_some())
                .count()
        })
        .sum::<usize>();
    let success = recovered == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy signer uses degree {DEGREE}, eta = {ETA}, tau = {TAU}, beta = tau·eta = {BETA}, and gamma2 = {GAMMA2}. A correct signer rejects ||r0||∞ >= gamma2 - beta = {}, but the vulnerable signer only rejects ||r0||∞ >= gamma2.",
                GAMMA2 - BETA
            ),
        )
        .step(
            "Low-bit edge",
            format!(
                "The attacker keeps only accepted signatures with at least one low-bit coefficient in gamma2 - beta <= |r0_j| < gamma2. From {EDGE_OBSERVATIONS} accepted boundary signatures, {edge_count} low-bit coordinates land in that forbidden band."
            ),
        )
        .step(
            "Oracle",
            "For each kept coordinate, r0_j = noise_j - (c·s2)_j. A candidate s2 is plausible when noise_j = r0_j + (c·s2)_j could have come from the low-bit noise range and survived the vulnerable check.",
        )
        .step(
            "Recovery",
            format!(
                "Exhaustive likelihood over s2 in [-eta, eta]^{DEGREE} recovers {:?}. The hidden toy s2 was {:?}.",
                recovered, secret
            ),
        )
        .step(
            "FIPS defense",
            "The gamma2 - beta rejection margin removes low-bit boundary values before they reach the signature transcript. Since ||c·s2||∞ <= beta, the margin prevents the secret-dependent shift from deciding whether r0 sits near a rounding edge.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "gamma2_lowbits_boundary_oracle",
            "Low-Bit Boundary Signatures Reveal s2",
            ChallengeMode::ToyParams,
            "uses gamma2 instead of gamma2 - beta when checking r0",
        ),
        transcript,
        success,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LowBitsObservation {
    challenge: Vec<i64>,
    edge_r0: Vec<Option<i64>>,
}

fn collect_lowbits_observations(secret: &[i64], target_count: usize) -> Vec<LowBitsObservation> {
    let mut rng = SplitMix64::new(PRNG_SEED);
    let mut observations = Vec::with_capacity(target_count);

    while observations.len() < target_count {
        let challenge = sample_sparse_challenge(&mut rng, secret.len());
        let c_times_secret = cyclic_convolution(&challenge, secret);
        let mut edge_r0 = vec![None; secret.len()];
        let mut vulnerable_accepts = true;

        for (index, &shift) in c_times_secret.iter().enumerate() {
            let noise = centered_lowbits_noise(&mut rng);
            let r0 = noise - shift;
            if r0.abs() >= GAMMA2 {
                vulnerable_accepts = false;
                break;
            }
            if r0.abs() >= GAMMA2 - BETA {
                edge_r0[index] = Some(r0);
            }
        }

        if vulnerable_accepts && edge_r0.iter().any(Option::is_some) {
            observations.push(LowBitsObservation { challenge, edge_r0 });
        }
    }

    observations
}

fn recover_secret_from_lowbits_oracle(observations: &[LowBitsObservation], eta: i64) -> Vec<i64> {
    let degree = observations
        .first()
        .map(|observation| observation.challenge.len())
        .expect("demo has observations");
    let mut current = Vec::with_capacity(degree);
    let mut best_secret = Vec::new();
    let mut best_score = f64::NEG_INFINITY;

    search_candidates(
        degree,
        eta,
        &mut current,
        observations,
        &mut best_secret,
        &mut best_score,
    );

    best_secret
}

fn search_candidates(
    degree: usize,
    eta: i64,
    current: &mut Vec<i64>,
    observations: &[LowBitsObservation],
    best_secret: &mut Vec<i64>,
    best_score: &mut f64,
) {
    if current.len() == degree {
        let score = lowbits_likelihood_score(current, observations);
        if score > *best_score {
            *best_score = score;
            *best_secret = current.clone();
        }
        return;
    }

    for coefficient in -eta..=eta {
        current.push(coefficient);
        search_candidates(degree, eta, current, observations, best_secret, best_score);
        current.pop();
    }
}

fn lowbits_likelihood_score(secret: &[i64], observations: &[LowBitsObservation]) -> f64 {
    observations
        .iter()
        .map(|observation| {
            observation
                .edge_r0
                .iter()
                .enumerate()
                .filter_map(|(edge_index, &edge_r0)| {
                    edge_r0.map(|r0| {
                        let shift = boundary_shift(&observation.challenge, secret, edge_index);
                        lowbits_log_likelihood(r0, shift)
                    })
                })
                .sum::<f64>()
        })
        .sum()
}

fn boundary_shift(challenge: &[i64], secret: &[i64], edge_index: usize) -> i64 {
    let degree = secret.len();
    challenge
        .iter()
        .enumerate()
        .filter(|&(_, &coefficient)| coefficient != 0)
        .map(|(challenge_index, &coefficient)| {
            coefficient * secret[(edge_index + degree - challenge_index) % degree]
        })
        .sum()
}

fn lowbits_log_likelihood(r0: i64, shift: i64) -> f64 {
    let noise = r0 + shift;
    if !(-(GAMMA2 - 1)..=(GAMMA2 - 1)).contains(&noise) || r0.abs() >= GAMMA2 {
        return -1_000_000.0;
    }

    -(accepted_noise_count(shift) as f64).ln()
}

fn accepted_noise_count(shift: i64) -> usize {
    (-(GAMMA2 - 1)..=(GAMMA2 - 1))
        .filter(|&noise| (noise - shift).abs() < GAMMA2)
        .count()
}

fn sample_sparse_challenge(rng: &mut SplitMix64, degree: usize) -> Vec<i64> {
    let mut challenge = vec![0; degree];
    let mut filled = 0;

    while filled < TAU {
        let index = rng.range(degree as u64) as usize;
        if challenge[index] != 0 {
            continue;
        }
        challenge[index] = if rng.bit() == 1 { 1 } else { -1 };
        filled += 1;
    }

    challenge
}

fn centered_lowbits_noise(rng: &mut SplitMix64) -> i64 {
    rng.range((2 * GAMMA2 - 1) as u64) as i64 - (GAMMA2 - 1)
}

fn cyclic_convolution(left: &[i64], right: &[i64]) -> Vec<i64> {
    let degree = right.len();
    let mut product = vec![0; degree];

    for output_index in 0..degree {
        for input_index in 0..degree {
            product[output_index] +=
                left[input_index] * right[(output_index + degree - input_index) % degree];
        }
    }

    product
}

fn secret_coefficients() -> Vec<i64> {
    vec![2, 0, -1, 1, -2, 1]
}

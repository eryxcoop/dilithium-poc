//! `gamma1_beta_boundary_oracle`: boundary signatures reveal a toy secret.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, SplitMix64, Transcript};

const ETA: i64 = 2;
const DEGREE: usize = 6;
const TAU: usize = 3;
const GAMMA1: i64 = 16;
const BETA: i64 = (TAU as i64) * ETA;
const EDGE_OBSERVATIONS: usize = 128;
const PRNG_SEED: u64 = 0x9a6d_01b0_7eda_f00d;

/// Runs the gamma1/beta boundary-oracle classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let observations = collect_boundary_observations(&secret, EDGE_OBSERVATIONS);
    let recovered = recover_secret_from_boundary_oracle(&observations, ETA);
    let edge_count = observations
        .iter()
        .map(|observation| {
            observation
                .edge_z
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
                "Toy signer uses degree {DEGREE}, eta = {ETA}, tau = {TAU}, beta = tau·eta = {BETA}, and gamma1 = {GAMMA1}. A correct signer rejects ||z||∞ >= gamma1 - beta = {}, but the vulnerable signer only rejects ||z||∞ >= gamma1.",
                GAMMA1 - BETA
            ),
        )
        .step(
            "Forbidden band",
            format!(
                "The attacker keeps only accepted signatures with at least one coefficient in gamma1 - beta <= |z_j| < gamma1. From {EDGE_OBSERVATIONS} accepted boundary signatures, {edge_count} coefficients land in that forbidden band."
            ),
        )
        .step(
            "Oracle",
            "For each kept coordinate, z_j = y_j + (c·s1)_j and y_j is still inside the mask range. Candidate secrets are scored by how likely they make the observed boundary z_j values.",
        )
        .step(
            "Recovery",
            format!(
                "Exhaustive likelihood over s1 in [-eta, eta]^{DEGREE} recovers {:?}. The hidden toy secret was {:?}.",
                recovered, secret
            ),
        )
        .step(
            "FIPS defense",
            "The gamma1 - beta rejection margin removes exactly this boundary band. Since ||c·s1||∞ <= beta, accepting only the inner range keeps z from revealing whether y was pushed toward an edge by the secret.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "gamma1_beta_boundary_oracle",
            "Boundary Signatures Reveal The Toy Secret",
            ChallengeMode::ToyParams,
            "uses gamma1 instead of gamma1 - beta when checking z",
        ),
        transcript,
        success,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundaryObservation {
    challenge: Vec<i64>,
    edge_z: Vec<Option<i64>>,
}

fn collect_boundary_observations(secret: &[i64], target_count: usize) -> Vec<BoundaryObservation> {
    let mut rng = SplitMix64::new(PRNG_SEED);
    let mut observations = Vec::with_capacity(target_count);

    while observations.len() < target_count {
        let challenge = sample_sparse_challenge(&mut rng, secret.len());
        let c_times_secret = cyclic_convolution(&challenge, secret);
        let mut edge_z = vec![None; secret.len()];
        let mut vulnerable_accepts = true;

        for (index, &shift) in c_times_secret.iter().enumerate() {
            let y = centered_mask(&mut rng);
            let z = y + shift;
            if z.abs() >= GAMMA1 {
                vulnerable_accepts = false;
                break;
            }
            if z.abs() >= GAMMA1 - BETA {
                edge_z[index] = Some(z);
            }
        }

        if vulnerable_accepts && edge_z.iter().any(Option::is_some) {
            observations.push(BoundaryObservation { challenge, edge_z });
        }
    }

    observations
}

fn recover_secret_from_boundary_oracle(observations: &[BoundaryObservation], eta: i64) -> Vec<i64> {
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
    observations: &[BoundaryObservation],
    best_secret: &mut Vec<i64>,
    best_score: &mut f64,
) {
    if current.len() == degree {
        let score = boundary_likelihood_score(current, observations);
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

fn boundary_likelihood_score(secret: &[i64], observations: &[BoundaryObservation]) -> f64 {
    observations
        .iter()
        .map(|observation| {
            observation
                .edge_z
                .iter()
                .enumerate()
                .filter_map(|(edge_index, &edge_z)| {
                    edge_z.map(|z| {
                        let shift = boundary_shift(&observation.challenge, secret, edge_index);
                        boundary_log_likelihood(z, shift)
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

fn boundary_log_likelihood(z: i64, shift: i64) -> f64 {
    let y = z - shift;
    if !(-(GAMMA1 - 1)..=(GAMMA1 - 1)).contains(&y) || z.abs() >= GAMMA1 {
        return -1_000_000.0;
    }

    -(accepted_mask_count(shift) as f64).ln()
}

fn accepted_mask_count(shift: i64) -> usize {
    (-(GAMMA1 - 1)..=(GAMMA1 - 1))
        .filter(|&y| (y + shift).abs() < GAMMA1)
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

fn centered_mask(rng: &mut SplitMix64) -> i64 {
    rng.range((2 * GAMMA1 - 1) as u64) as i64 - (GAMMA1 - 1)
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
    vec![1, -2, 2, 0, -1, 1]
}

//! `gamma2_lowbits_pruned_recovery`: prune low-bit constraints to recover `s2`.

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, SplitMix64, Transcript};

const ETA: i64 = 2;
const DEGREE: usize = 20;
const TAU: usize = 4;
const GAMMA2: i64 = 24;
const BETA: i64 = (TAU as i64) * ETA;
const EDGE_OBSERVATIONS: usize = 128;
const PRNG_SEED: u64 = 0x0000_0000_00ab_c123;

/// Runs the advanced gamma2 low-bits pruning classroom demo.
pub fn run() -> ChallengeRun {
    let secret = secret_coefficients();
    let observations = collect_lowbits_observations(&secret, EDGE_OBSERVATIONS);
    let constraints = constraints_from_observations(&observations);
    let search = recover_secret_with_pruning(&constraints, DEGREE, ETA);
    let naive_candidates = (2 * ETA as u128 + 1).pow(DEGREE as u32);
    let success = search.secret == secret;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Advanced toy signer uses degree {DEGREE}, eta = {ETA}, tau = {TAU}, beta = {BETA}, and gamma2 = {GAMMA2}. Brute force over [-eta, eta]^{DEGREE} would test {naive_candidates} candidates."
            ),
        )
        .step(
            "Boundary constraints",
            format!(
                "From {EDGE_OBSERVATIONS} accepted signatures, the attacker extracts {} low-bit edge constraints of the form L <= (c·s2)_j <= U.",
                constraints.len()
            ),
        )
        .step(
            "Pruning",
            format!(
                "Backtracking assigns coefficients in occurrence order. At each partial assignment it checks whether partial ± missing·eta still intersects every constraint interval. The search visits {} nodes and leaves {} feasible candidates.",
                search.visited_nodes, search.feasible_candidates
            ),
        )
        .step(
            "Recovery",
            format!(
                "Likelihood ranking among feasible candidates recovers {:?}. The hidden toy s2 was {:?}.",
                search.secret, secret
            ),
        )
        .step(
            "FIPS defense",
            "The gamma2 - beta rejection margin prevents these low-bit edge constraints from entering the transcript. Without the edge samples, the pruning oracle has no constraints to accumulate.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "gamma2_lowbits_pruned_recovery",
            "Pruned Low-Bit Constraints Recover s2",
            ChallengeMode::ToyParams,
            "uses gamma2 instead of gamma2 - beta, then recovers s2 with pruned boundary constraints",
        ),
        transcript,
        success,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrunedLowBitsObservation {
    challenge: Vec<i64>,
    edge_r0: Vec<Option<i64>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundaryConstraint {
    terms: Vec<(usize, i64)>,
    lower: i64,
    upper: i64,
    r0: i64,
}

#[derive(Clone, Debug, PartialEq)]
struct SearchResult {
    secret: Vec<i64>,
    visited_nodes: usize,
    feasible_candidates: usize,
}

fn collect_lowbits_observations(
    secret: &[i64],
    target_count: usize,
) -> Vec<PrunedLowBitsObservation> {
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
            observations.push(PrunedLowBitsObservation { challenge, edge_r0 });
        }
    }

    observations
}

fn constraints_from_observations(
    observations: &[PrunedLowBitsObservation],
) -> Vec<BoundaryConstraint> {
    observations
        .iter()
        .flat_map(|observation| {
            observation
                .edge_r0
                .iter()
                .enumerate()
                .filter_map(|(edge_index, &edge_r0)| {
                    edge_r0.map(|r0| {
                        let terms = observation
                            .challenge
                            .iter()
                            .enumerate()
                            .filter_map(|(challenge_index, &coefficient)| {
                                (coefficient != 0).then_some((
                                    (edge_index + DEGREE - challenge_index) % DEGREE,
                                    coefficient,
                                ))
                            })
                            .collect();
                        BoundaryConstraint {
                            terms,
                            lower: -(GAMMA2 - 1) - r0,
                            upper: (GAMMA2 - 1) - r0,
                            r0,
                        }
                    })
                })
        })
        .collect()
}

fn recover_secret_with_pruning(
    constraints: &[BoundaryConstraint],
    degree: usize,
    eta: i64,
) -> SearchResult {
    let assignment_order = variable_order(constraints, degree);
    let constraints_by_variable = constraints_by_variable(constraints, degree);
    let mut assignment = vec![None; degree];
    let mut best_secret = Vec::new();
    let mut best_score = f64::NEG_INFINITY;
    let mut visited_nodes = 0;
    let mut feasible_candidates = 0;

    search_pruned(
        constraints,
        eta,
        &assignment_order,
        &constraints_by_variable,
        &mut assignment,
        0,
        &mut best_secret,
        &mut best_score,
        &mut visited_nodes,
        &mut feasible_candidates,
    );

    SearchResult {
        secret: best_secret,
        visited_nodes,
        feasible_candidates,
    }
}

#[allow(clippy::too_many_arguments)]
fn search_pruned(
    constraints: &[BoundaryConstraint],
    eta: i64,
    assignment_order: &[usize],
    constraints_by_variable: &[Vec<usize>],
    assignment: &mut [Option<i64>],
    depth: usize,
    best_secret: &mut Vec<i64>,
    best_score: &mut f64,
    visited_nodes: &mut usize,
    feasible_candidates: &mut usize,
) {
    *visited_nodes += 1;

    if depth == assignment_order.len() {
        *feasible_candidates += 1;
        let candidate = assignment
            .iter()
            .map(|coefficient| coefficient.expect("complete assignment"))
            .collect::<Vec<_>>();
        let score = lowbits_likelihood_score(&candidate, constraints);
        if score > *best_score {
            *best_score = score;
            *best_secret = candidate;
        }
        return;
    }

    let variable = assignment_order[depth];
    for coefficient in -eta..=eta {
        assignment[variable] = Some(coefficient);
        if affected_constraints_remain_possible(
            constraints,
            &constraints_by_variable[variable],
            assignment,
            eta,
        ) {
            search_pruned(
                constraints,
                eta,
                assignment_order,
                constraints_by_variable,
                assignment,
                depth + 1,
                best_secret,
                best_score,
                visited_nodes,
                feasible_candidates,
            );
        }
    }
    assignment[variable] = None;
}

fn affected_constraints_remain_possible(
    constraints: &[BoundaryConstraint],
    affected_indices: &[usize],
    assignment: &[Option<i64>],
    eta: i64,
) -> bool {
    affected_indices.iter().all(|&constraint_index| {
        let constraint = &constraints[constraint_index];
        let (partial, missing) = partial_shift_range(&constraint.terms, assignment, eta);
        partial - missing <= constraint.upper && partial + missing >= constraint.lower
    })
}

fn partial_shift_range(terms: &[(usize, i64)], assignment: &[Option<i64>], eta: i64) -> (i64, i64) {
    let mut partial = 0;
    let mut missing = 0;

    for &(index, sign) in terms {
        match assignment[index] {
            Some(value) => partial += sign * value,
            None => missing += eta,
        }
    }

    (partial, missing)
}

fn variable_order(constraints: &[BoundaryConstraint], degree: usize) -> Vec<usize> {
    let mut occurrences = vec![0usize; degree];
    for constraint in constraints {
        for &(index, _) in &constraint.terms {
            occurrences[index] += 1;
        }
    }

    let mut order = (0..degree).collect::<Vec<_>>();
    order.sort_by_key(|&index| std::cmp::Reverse(occurrences[index]));
    order
}

fn constraints_by_variable(constraints: &[BoundaryConstraint], degree: usize) -> Vec<Vec<usize>> {
    let mut by_variable = vec![Vec::new(); degree];

    for (constraint_index, constraint) in constraints.iter().enumerate() {
        for &(variable, _) in &constraint.terms {
            by_variable[variable].push(constraint_index);
        }
    }

    by_variable
}

fn lowbits_likelihood_score(secret: &[i64], constraints: &[BoundaryConstraint]) -> f64 {
    constraints
        .iter()
        .map(|constraint| {
            let shift = constraint
                .terms
                .iter()
                .map(|&(index, sign)| sign * secret[index])
                .sum::<i64>();
            lowbits_log_likelihood(constraint.r0, shift)
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
    (0..DEGREE)
        .map(|index| (index as i64 * 7 + 3).rem_euclid(2 * ETA + 1) - ETA)
        .collect()
}

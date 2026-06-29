//! Shared deterministic search helpers for toy challenge runners.

use crate::toy::{ToyParams, ToyPoly};

use super::SplitMix64;

/// Returns deterministic bounded toy polynomials generated from a fixed seed.
pub fn random_bounded_polys(
    params: ToyParams,
    bound: i64,
    count: usize,
    seed: u64,
) -> impl Iterator<Item = ToyPoly> {
    let mut rng = SplitMix64::new(seed);
    (0..count).map(move |_| {
        let coeffs = (0..params.degree())
            .map(|_| rng.range((2 * bound + 1) as u64) as i64 - bound)
            .collect::<Vec<_>>();
        ToyPoly::from_coeffs(params, coeffs).expect("candidate length matches toy degree")
    })
}

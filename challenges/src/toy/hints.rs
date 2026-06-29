//! Toy hint utilities used by educational verifier demos.

use super::{ToyParams, ToyPoly};

/// Returns the total number of `true` hint entries.
pub fn hint_weight(hints: &[bool]) -> usize {
    hints.iter().filter(|&&hint| hint).count()
}

/// Returns the first positions where the hint vector is set.
pub fn first_hint_positions(hints: &[bool], count: usize) -> Vec<usize> {
    hints
        .iter()
        .enumerate()
        .filter_map(|(index, hint)| hint.then_some(index))
        .take(count)
        .collect()
}

/// Decodes a dense bit mask into a toy hint vector of width `width`.
pub fn bits_from_mask(mask: usize, width: usize) -> Vec<bool> {
    (0..width)
        .map(|bit_index| ((mask >> bit_index) & 1) == 1)
        .collect()
}

/// Applies the toy `UseHint` analogue coefficientwise.
pub fn use_hints(poly: &ToyPoly, hints: &[bool], gamma2: i64) -> Vec<u8> {
    poly.coeffs()
        .iter()
        .zip(hints.iter())
        .map(|(&coefficient, &hint)| {
            let (high, low) = decompose(poly.params(), coefficient, gamma2);
            if !hint {
                return high;
            }
            if low > 0 {
                (high + 1) % high_modulus(poly.params(), gamma2)
            } else {
                ((high as i64) - 1).rem_euclid(high_modulus(poly.params(), gamma2) as i64) as u8
            }
        })
        .collect()
}

/// Returns the toy high/low decomposition used by hint-based demos.
pub fn decompose(params: ToyParams, coefficient: i64, gamma2: i64) -> (u8, i64) {
    let alpha = 2 * gamma2;
    let reduced = params.reduce(coefficient);
    let mut best: Option<(i64, bool, u8, i64)> = None;

    for high in 0..high_modulus(params, gamma2) {
        let low = params.centered(reduced - high as i64 * alpha);
        if low.abs() > gamma2 {
            continue;
        }

        let candidate = (low.abs(), low <= 0, high, low);
        if best.map(|current| candidate < current).unwrap_or(true) {
            best = Some(candidate);
        }
    }

    let (_, _, high, low) = best.expect("toy params should admit a decomposition");
    (high, low)
}

fn high_modulus(params: ToyParams, gamma2: i64) -> u8 {
    ((params.modulus() - 1) / (2 * gamma2)) as u8
}

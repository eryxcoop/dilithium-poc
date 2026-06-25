//! Exercise for `verifier_no_omega`.

/// Returns whether a strict verifier should accept a toy hint vector.
///
/// Complete this by enforcing the FIPS-style `h` weight bound `weight <= ω`.
pub fn strict_hint_weight_accepts(weight: usize, omega: usize) -> bool {
    let _ = (weight, omega);
    todo!("accept only when hint weight is at most ω")
}

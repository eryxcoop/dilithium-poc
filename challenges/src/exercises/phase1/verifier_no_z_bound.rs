//! Exercise for `verifier_no_z_bound`.

/// Returns whether a strict verifier should accept `z` under the toy bound.
///
/// Complete this by checking `||z||∞ < γ₁ - β`, represented here by
/// `z_infinity_norm < bound`.
pub fn strict_z_bound_accepts(z_infinity_norm: i64, bound: i64) -> bool {
    let _ = (z_infinity_norm, bound);
    todo!("accept only when ||z||∞ < γ₁ - β")
}

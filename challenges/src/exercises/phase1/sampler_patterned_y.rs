//! Exercise for `sampler_patterned_y`.

/// Recovers toy secret coefficients when the signer exposes a patterned `y`.
///
/// The response is `z = y + c·s₁` coefficient-wise modulo `q`. Complete this
/// for the classroom case where `c = 1`.
pub fn recover_secret_from_patterned_mask(z: &[i64], patterned_y: &[i64], q: i64) -> Vec<i64> {
    let _ = (z, patterned_y, q);
    todo!("recover s₁ coefficients from z - y")
}

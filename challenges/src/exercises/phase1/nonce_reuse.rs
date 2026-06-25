//! Exercise for `nonce_reuse`.

/// Recovers `s₁` from two toy signatures that reused the same mask.
pub fn recover_secret_from_reused_mask(z1: i64, z2: i64, c1: i64, c2: i64, q: i64) -> i64 {
    let _ = (z1, z2, c1, c2, q);
    todo!("recover the toy secret")
}

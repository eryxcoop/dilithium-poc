//! # Nonce reuse
//!
//! Two signatures land on your desk. Different messages, different
//! challenges, same mask.
//!
//! In this toy signer the response has the familiar shape
//!
//! ```text
//! z = y + c·s₁ mod q
//! ```
//!
//! The implementation made one fatal economy: it reused `y`. Your job is to
//! recover the secret coefficient `s₁` from the two public transcripts.
//!
//! You are given `z₁`, `z₂`, `c₁`, `c₂`, and `q`. Return the value of `s₁`
//! modulo `q`. The challenge is deliberately one-dimensional; the lesson is
//! the cancellation, not polynomial bookkeeping.
//!
//! **Win condition:** make the recovery work without guessing the mask.

/// Recovers `s₁` from two toy signatures that reused the same mask.
pub fn recover_secret_from_reused_mask(z1: i64, z2: i64, c1: i64, c2: i64, q: i64) -> i64 {
    let _ = (z1, z2, c1, c2, q);
    todo!("recover the toy secret")
}

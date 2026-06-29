//! # Too small to hide
//!
//! Cryptography often fails quietly when the numbers stop being large.
//!
//! This toy public key has collapsed ML-DSA down to a single modular equation:
//!
//! ```text
//! public = a·s mod q
//! ```
//!
//! There is no lattice hardness left to admire. There is only a tiny search
//! space and a secret sitting inside it.
//!
//! Write the boring attack. Try candidate secrets until the public equation
//! matches.
//!
//! **Win condition:** return the matching secret modulo `q`, or `None` when no
//! candidate satisfies the equation.

/// Recovers a one-dimensional toy secret from a tiny public equation.
pub fn recover_toy_secret_by_search(a: i64, public: i64, q: i64) -> Option<i64> {
    let _ = (a, public, q);
    todo!("recover the toy secret")
}

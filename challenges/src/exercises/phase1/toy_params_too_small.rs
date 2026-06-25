//! Exercise for `toy_params_too_small`.

/// Recovers a one-dimensional toy secret by exhaustive search.
///
/// The public equation is `public = a·s₁ mod q`. Complete this by trying every
/// candidate in `[0, q)`.
pub fn recover_toy_secret_by_search(a: i64, public: i64, q: i64) -> Option<i64> {
    let _ = (a, public, q);
    todo!("try every candidate s₁ and return the one matching a·s₁ mod q")
}

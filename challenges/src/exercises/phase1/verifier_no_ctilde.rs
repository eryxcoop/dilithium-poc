//! Exercise for `verifier_no_ctilde`.

/// Returns whether a strict verifier should accept the supplied challenge seed.
///
/// Complete this by enforcing `c̃ == H(μ || w1Encode(w₁′))`, represented here
/// by exact equality between the supplied and recomputed toy strings.
pub fn strict_ctilde_accepts(supplied_ctilde: &str, recomputed_ctilde: &str) -> bool {
    let _ = (supplied_ctilde, recomputed_ctilde);
    todo!("accept only when supplied c̃ matches recomputed c̃′")
}

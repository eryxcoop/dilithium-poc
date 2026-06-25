//! Exercise for `verifier_no_ctilde`.

/// Returns whether a strict verifier should accept the supplied challenge seed.
pub fn strict_ctilde_accepts(supplied_ctilde: &str, recomputed_ctilde: &str) -> bool {
    let _ = (supplied_ctilde, recomputed_ctilde);
    todo!("implement the strict verifier decision")
}

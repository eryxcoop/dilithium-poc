//! Exercise for `lambda_too_short_cross_message`.

use crate::toy::{ToyParams, ToyPoly};

/// Forges a toy signature for the unsigned message by exploiting a 24-bit
/// cross-message collision in `c̃`.
pub fn forge_cross_message_with_short_lambda(
    signed_message: &[u8],
    forged_message: &[u8],
    context: &[u8],
) -> ([u8; 4], ToyPoly) {
    let params = exercise_params();
    let signed_candidates = bounded_candidates(params, 3, 12_000, 0x00aa_aa11_2233_4455);
    let forged_candidates = bounded_candidates(params, 5, 30_000, 0x00bb_bb66_7788_99aa);

    let _ = (
        signed_message,
        forged_message,
        context,
        signed_candidates,
        forged_candidates,
    );
    todo!("find a signed-message challenge seed and reuse it on an unsigned message")
}

/// Derives the toy message representative for the short-`λ` challenge.
#[allow(dead_code)]
fn message_representative(message: &[u8], context: &[u8]) -> [u8; 8] {
    let _ = (message, context);
    todo!("derive the toy mu used by the challenge")
}

/// Recomputes the full 32-bit toy challenge seed.
#[allow(dead_code)]
fn full_challenge_seed(mu: &[u8; 8], w1: &[u8]) -> [u8; 4] {
    let _ = (mu, w1);
    todo!("derive the full toy c_tilde")
}

/// Returns the first 24 bits of the full challenge seed.
#[allow(dead_code)]
fn short_prefix_24(c_tilde_full: &[u8; 4]) -> u32 {
    let _ = c_tilde_full;
    todo!("truncate the challenge seed to its checked 24-bit prefix")
}

/// Returns the deterministic toy public key `(a, t)` and secret `s` used by
/// the classroom challenge.
#[allow(dead_code)]
fn toy_signing_key(params: ToyParams) -> (ToyPoly, ToyPoly, ToyPoly) {
    let _ = params;
    todo!("construct the fixed toy public key and secret")
}

/// Returns deterministic bounded toy polynomials for the collision search.
#[allow(dead_code)]
fn bounded_candidates(params: ToyParams, bound: i64, count: usize, seed: u64) -> Vec<ToyPoly> {
    let _ = (params, bound, count, seed);
    todo!("enumerate deterministic bounded toy polynomials")
}

#[allow(dead_code)]
fn exercise_params() -> ToyParams {
    ToyParams::new(8, 257).expect("toy params should be valid")
}

//! Exercise for `toy_dense_hint_forgery`.

use crate::toy::{ToyParams, ToyPoly};

/// Forges a toy signature `(c_tilde, z, hints)` for the fixed dense-hint
/// classroom setup without using the private key.
pub fn forge_signature_with_dense_hints(
    message: &[u8],
    context: &[u8],
) -> (u8, ToyPoly, Vec<bool>) {
    let params = exercise_params();
    let z_candidates = generate_z_candidates(params);
    let target_mu = toy_message_representative(message, context);

    let _ = (z_candidates, target_mu);
    todo!("search for a toy forgery that needs weight(h) > omega")
}

/// Returns the toy message representative for the dense-hint challenge.
#[allow(dead_code)]
fn toy_message_representative(message: &[u8], context: &[u8]) -> u8 {
    let _ = (message, context);
    todo!("derive the toy mu used by the forgery challenge")
}

/// Recomputes the toy challenge seed from `mu` and reconstructed `w1'`.
#[allow(dead_code)]
fn toy_challenge_seed(mu: u8, w1: &[u8]) -> u8 {
    let _ = (mu, w1);
    todo!("derive the toy c_tilde from mu and w1'")
}

/// Returns the deterministic public key pair `(a, t1)` used by the toy
/// forgery challenge.
#[allow(dead_code)]
fn toy_public_key(params: ToyParams) -> (ToyPoly, ToyPoly) {
    let _ = params;
    todo!("construct the fixed toy public key")
}

/// Returns bounded `z` candidates for the dense-hint search.
#[allow(dead_code)]
fn generate_z_candidates(params: ToyParams) -> Vec<ToyPoly> {
    let _ = params;
    todo!("enumerate bounded z candidates")
}

#[allow(dead_code)]
fn exercise_params() -> ToyParams {
    ToyParams::new(8, 97).expect("toy params should be valid")
}

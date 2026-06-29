//! # The missing `c̃` check
//!
//! A verifier reconstructs `w₁′`, nods at the bounds, accepts the hint
//! encoding... and forgets the last line.
//!
//! In ML-DSA, the challenge seed is supposed to come back and bind the whole
//! transcript:
//!
//! ```text
//! c̃ ?= H(μ || w1Encode(w₁′))
//! ```
//!
//! This exercise removes that final comparison. Your task is to build a
//! structurally valid signature for an arbitrary `(message, context)` without
//! knowing the private key.
//!
//! The helpers below are intentionally empty. Fill them in like a forger would:
//! format the message, derive a plausible-looking `c̃`, choose a bounded
//! nonzero `z`, attach valid hints, and encode the result at the exact
//! ML-DSA-44 length.
//!
//! **Win condition:** the broken verifier accepts; the real verifier would
//! reject because `c̃` is not actually bound to `w₁′`.

use dilithium_poc::hints::HintsVector;
use dilithium_poc::ml_dsa::{PublicKey, Signature};
use dilithium_poc::params::{ML_DSA_44, ParameterSet};
use dilithium_poc::poly::PolyVector;

/// Builds a signature for `message` and `context` that a verifier missing the
/// final `c̃` binding check would accept.
pub fn forge_signature_without_ctilde_binding(
    public_key: &PublicKey,
    message: &[u8],
    context: &[u8],
) -> Signature {
    let parameter_set = public_key.parameter_set();
    let c_tilde = derive_target_ctilde(public_key, message, context);
    let z = build_bounded_z(parameter_set);
    let hints = build_valid_hints(parameter_set);

    assemble_signature(parameter_set, &c_tilde, &z, &hints)
}

/// Formats the message the same way external ML-DSA signing and verification do.
#[allow(dead_code)]
fn format_message(message: &[u8], context: &[u8]) -> Vec<u8> {
    let _ = (message, context);
    todo!("format M' = 0x00 || len(ctx) || ctx || M")
}

/// Derives a challenge seed tied to the target inputs, but not to any
/// reconstructed `w₁′`.
#[allow(dead_code)]
fn derive_target_ctilde(public_key: &PublicKey, message: &[u8], context: &[u8]) -> Vec<u8> {
    let _ = (public_key, message, context);
    todo!("derive a target-dependent but unauthenticated c_tilde")
}

/// Builds a simple nonzero `z` that stays within the signing bound checks.
#[allow(dead_code)]
fn build_bounded_z(parameter_set: ParameterSet) -> PolyVector {
    let _ = parameter_set;
    todo!("construct a bounded, nonzero z vector")
}

/// Builds a hint vector that satisfies the verifier's structural checks.
#[allow(dead_code)]
fn build_valid_hints(parameter_set: ParameterSet) -> HintsVector {
    let _ = parameter_set;
    todo!("construct valid hints, for example all-zero hints")
}

/// Encodes the forged pieces as a structurally valid ML-DSA signature.
#[allow(dead_code)]
fn assemble_signature(
    parameter_set: ParameterSet,
    c_tilde: &[u8],
    z: &PolyVector,
    hints: &HintsVector,
) -> Signature {
    let _ = (parameter_set, c_tilde, z, hints);
    todo!("encode the forged signature with exact ML-DSA length")
}

#[allow(dead_code)]
fn exercise_parameter_set() -> ParameterSet {
    ML_DSA_44
}

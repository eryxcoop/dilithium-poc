//! Exercise for `verifier_no_ctilde`.

use dilithium_poc::ml_dsa::{PublicKey, Signature};

/// Builds a signature for `message` and `context` that a verifier missing the
/// final `c̃` binding check would accept.
pub fn forge_signature_without_ctilde_binding(
    public_key: &PublicKey,
    message: &[u8],
    context: &[u8],
) -> Signature {
    let _ = (public_key, message, context);
    todo!("forge a signature accepted by the broken verifier")
}

//! Shared helpers for toy truncated-challenge demos.

use dilithium_poc::xof::shake256;

/// Byte length of the toy message representative `μ`.
pub const TOY_MESSAGE_REPRESENTATIVE_BYTES: usize = 8;

/// Returns the toy message representative `μ = H(ctx || ':' || message)`.
pub fn toy_message_representative(
    message: &[u8],
    context: &[u8],
) -> [u8; TOY_MESSAGE_REPRESENTATIVE_BYTES] {
    let mut input = Vec::with_capacity(context.len() + 1 + message.len());
    input.extend_from_slice(context);
    input.push(b':');
    input.extend_from_slice(message);
    let digest = shake256(&input, TOY_MESSAGE_REPRESENTATIVE_BYTES);
    let mut mu = [0u8; TOY_MESSAGE_REPRESENTATIVE_BYTES];
    mu.copy_from_slice(&digest);
    mu
}

/// Returns a fixed-width toy Fiat-Shamir challenge seed.
pub fn toy_full_challenge_seed<const N: usize>(
    mu: &[u8; TOY_MESSAGE_REPRESENTATIVE_BYTES],
    w1: &[u8],
) -> [u8; N] {
    let mut input = Vec::with_capacity(mu.len() + w1.len());
    input.extend_from_slice(mu);
    input.extend_from_slice(w1);
    let digest = shake256(&input, N);
    let mut full = [0u8; N];
    full.copy_from_slice(&digest);
    full
}

/// Returns the first 24 bits of a 32-bit toy challenge seed.
pub fn short_prefix_24(c_tilde_full: &[u8; 4]) -> u32 {
    ((c_tilde_full[0] as u32) << 16) | ((c_tilde_full[1] as u32) << 8) | c_tilde_full[2] as u32
}

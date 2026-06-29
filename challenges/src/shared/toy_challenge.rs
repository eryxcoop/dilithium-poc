//! Shared toy challenge/hash helpers for classroom demos.

/// Returns a small toy message representative for weighted-sum demos.
pub fn toy_u8_message_representative(message: &[u8], context: &[u8], modulus: u8) -> u8 {
    let weighted_sum = context
        .iter()
        .chain(core::iter::once(&b':'))
        .chain(message.iter())
        .enumerate()
        .map(|(index, byte)| (index as u32 + 1) * (*byte as u32))
        .sum::<u32>();
    (weighted_sum % modulus as u32) as u8
}

/// Returns a weighted-sum toy challenge seed from `mu` and `w1`.
pub fn toy_u8_challenge_seed(mu: u8, w1: &[u8], modulus: u8) -> u8 {
    let weighted_sum = w1
        .iter()
        .enumerate()
        .map(|(index, value)| (index as u32 + 5) * (*value as u32))
        .sum::<u32>();
    ((mu as u32 + weighted_sum) % modulus as u32) as u8
}

/// Samples a ternary toy challenge from a single-byte seed.
pub fn sample_ternary_seed(seed: u8) -> i64 {
    match seed % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

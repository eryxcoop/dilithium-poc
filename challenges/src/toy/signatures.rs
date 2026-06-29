//! Toy signing/verifying helper types shared across classroom demos.

use super::ToyPoly;

use crate::toy::decompose;

/// Public toy algebra data analogous to `(a, t)` in classroom verifier demos.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyPublicKey {
    /// Public matrix/polynomial analogue used to form commitments.
    pub a: ToyPoly,
    /// Public key image derived from the secret.
    pub t: ToyPoly,
}

/// Toy signing key material consisting of public data plus one secret
/// polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToySigningKey {
    /// Public verifier-facing data.
    pub public_key: ToyPublicKey,
    /// Secret toy polynomial.
    pub secret: ToyPoly,
}

/// Simple `(c_tilde, z)` toy signature container for transcript-binding demos.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyChallengeSignature<const N: usize> {
    /// Toy challenge seed bytes.
    pub c_tilde: [u8; N],
    /// Toy response polynomial.
    pub z: ToyPoly,
}

/// Simple `(c_tilde, z, hints, w_approx)` toy signature container for hint-based demos.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyHintSignature {
    /// Small toy challenge seed.
    pub c_tilde: u8,
    /// Toy response polynomial.
    pub z: ToyPoly,
    /// Dense or sparse hint bits used by the demo.
    pub hints: Vec<bool>,
    /// Reconstructed toy `w_approx`.
    pub w_approx: ToyPoly,
}

/// Reconstructs the toy analogue of `w_approx = a·z - c·t`.
pub fn reconstruct_w_approx(public_key: &ToyPublicKey, z: &ToyPoly, challenge: i64) -> ToyPoly {
    let a_z = public_key.a.checked_mul(z).expect("matching toy params");
    let c_t = public_key.t.scalar_mul(challenge);
    a_z.checked_sub(&c_t).expect("matching toy params")
}

/// Returns high bits for every coefficient in the toy polynomial.
pub fn high_bits_vector(poly: &ToyPoly, gamma2: i64) -> Vec<u8> {
    poly.coeffs()
        .iter()
        .map(|&coefficient| decompose(poly.params(), coefficient, gamma2).0)
        .collect()
}

/// Samples a ternary toy scalar challenge from the first challenge byte.
pub fn sample_ternary_challenge(first_byte: u8) -> i64 {
    match first_byte % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

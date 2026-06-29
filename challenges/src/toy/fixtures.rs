//! Fixed toy key material shared across classroom demos.

use super::{ToyParams, ToyPoly, ToyPublicKey, ToySigningKey};

/// Returns the fixed toy signing key used by the dense-hint forgery demo.
pub fn dense_hint_signing_key(params: ToyParams) -> ToySigningKey {
    let a = ToyPoly::from_coeffs(params, [3, 0, 1, 4, 0, 2, 0, 1]).expect("length is valid");
    let secret =
        ToyPoly::from_coeffs(params, [2, -2, 1, 0, -1, 2, 1, 0]).expect("length is valid");
    let t = a.checked_mul(&secret).expect("matching toy params");

    ToySigningKey {
        public_key: ToyPublicKey { a, t },
        secret,
    }
}

/// Returns the fixed toy signing key used by the short-λ cross-message demo.
pub fn short_lambda_signing_key(params: ToyParams) -> ToySigningKey {
    let a = ToyPoly::from_coeffs(params, [3, 1, 0, 2, 0, 1, 0, 4]).expect("length is valid");
    let secret =
        ToyPoly::from_coeffs(params, [1, -2, 2, 0, -1, 1, 0, 2]).expect("length is valid");
    let t = a.checked_mul(&secret).expect("matching toy params");

    ToySigningKey {
        public_key: ToyPublicKey { a, t },
        secret,
    }
}

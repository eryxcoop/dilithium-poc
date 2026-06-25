use super::*;
use crate::ml_dsa::{
    keygen, keygen_from_seed, sign, sign_deterministic_for_test,
    sign_deterministic_for_test_with_report, verify,
};

const TEST_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn keygen_from_seed_produces_exact_fips_sizes() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();

    assert_eq!(
        key_pair.public_key().as_bytes().len(),
        ML_DSA_44.sizes.public_key_bytes
    );
    assert_eq!(
        key_pair.private_key().as_bytes().len(),
        ML_DSA_44.sizes.private_key_bytes
    );
}

#[test]
fn deterministic_signature_verifies_and_reports_attempts() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let message = b"m4 deterministic signing";
    let context = b"poc";

    let signed =
        sign_deterministic_for_test_with_report(key_pair.private_key(), message, context).unwrap();

    assert!(signed.report().attempts() >= 1);
    assert!(verify(key_pair.public_key(), message, signed.signature(), context).unwrap());
}

#[test]
fn deterministic_signing_reports_attempts_for_all_parameter_sets() {
    for parameter_set in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        let key_pair = keygen_from_seed(parameter_set, TEST_SEED).unwrap();
        let message = format!("attempt instrumentation for {}", parameter_set.name);
        let signed = sign_deterministic_for_test_with_report(
            key_pair.private_key(),
            message.as_bytes(),
            b"m4",
        )
        .unwrap();

        assert!(signed.report().attempts() >= 1);
        assert!(
            verify(
                key_pair.public_key(),
                message.as_bytes(),
                signed.signature(),
                b"m4"
            )
            .unwrap()
        );
    }
}

#[test]
fn hedged_signature_verifies() {
    let key_pair = keygen(ML_DSA_44).unwrap();
    let signature = sign(key_pair.private_key(), b"m4 hedged signing", b"").unwrap();

    assert!(verify(key_pair.public_key(), b"m4 hedged signing", &signature, b"").unwrap());
}

#[test]
fn altered_message_signature_or_public_key_fails_verification() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let message = b"message";
    let signature = sign_deterministic_for_test(key_pair.private_key(), message, b"ctx").unwrap();

    assert!(!verify(key_pair.public_key(), b"messagf", &signature, b"ctx").unwrap());

    let mut altered_signature = signature.as_bytes().to_vec();
    altered_signature[0] ^= 0x01;
    let altered_signature = Signature::from_raw(ML_DSA_44, altered_signature).unwrap();
    assert!(!verify(key_pair.public_key(), message, &altered_signature, b"ctx").unwrap());

    let mut altered_public_key = key_pair.public_key().as_bytes().to_vec();
    altered_public_key[0] ^= 0x01;
    let altered_public_key = PublicKey::from_raw(ML_DSA_44, altered_public_key).unwrap();
    assert!(!verify(&altered_public_key, message, &signature, b"ctx").unwrap());
}

#[test]
fn context_is_part_of_the_signed_domain() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let message = b"context binding regression";
    let signature =
        sign_deterministic_for_test(key_pair.private_key(), message, b"domain-a").unwrap();

    assert!(verify(key_pair.public_key(), message, &signature, b"domain-a").unwrap());
    assert!(!verify(key_pair.public_key(), message, &signature, b"domain-b").unwrap());
}

#[test]
fn verifier_rejects_parameter_set_mismatch() {
    let public_key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let signature_key_pair = keygen_from_seed(ML_DSA_65, [0x42; 32]).unwrap();
    let signature =
        sign_deterministic_for_test(signature_key_pair.private_key(), b"parameter set", b"")
            .unwrap();

    assert!(!verify(
        public_key_pair.public_key(),
        b"parameter set",
        &signature,
        b""
    )
    .unwrap());
}

#[test]
fn verifier_rejects_structurally_valid_signature_when_z_exceeds_infinity_norm_bound() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let message = b"z infinity norm regression";
    let signature = sign_deterministic_for_test(key_pair.private_key(), message, b"").unwrap();
    let parts = sig_decode(signature.as_bytes(), ML_DSA_44).unwrap();
    let bound = (ML_DSA_44.core.gamma1 - ML_DSA_44.core.beta) as i32;

    let mut z_polys = vec![Poly::zero(); ML_DSA_44.core.l];
    z_polys[0] = poly_with_coefficients(&[(0, bound)]);
    let out_of_bounds_z = PolyVector::from_polys(ML_DSA_44.core.l, z_polys).unwrap();
    let encoded = sig_encode(
        &parts.c_tilde,
        &out_of_bounds_z,
        &parts.hints,
        ML_DSA_44,
    )
    .unwrap();
    let out_of_bounds_signature = Signature::from_raw(ML_DSA_44, encoded).unwrap();

    assert!(!verify(
        key_pair.public_key(),
        message,
        &out_of_bounds_signature,
        b""
    )
    .unwrap());
}

#[test]
fn context_longer_than_255_bytes_is_rejected() {
    let key_pair = keygen_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let too_long = vec![0u8; 256];

    assert_eq!(
        sign_deterministic_for_test(key_pair.private_key(), b"message", &too_long).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 255,
            actual: 256,
            item: "context",
        }
    );

    let signature = sign_deterministic_for_test(key_pair.private_key(), b"message", b"").unwrap();
    assert_eq!(
        verify(key_pair.public_key(), b"message", &signature, &too_long).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 255,
            actual: 256,
            item: "context",
        }
    );
}

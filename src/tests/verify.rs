use super::*;

#[test]
fn verify_lengths_rejects_public_key_or_signature_length_mismatch() {
    let public_key = vec![0u8; ML_DSA_44.sizes.public_key_bytes];
    let signature = vec![0u8; ML_DSA_44.sizes.signature_bytes];

    assert!(verify_lengths(&public_key, &signature, ML_DSA_44));
    assert!(!verify_lengths(
        &public_key[..public_key.len() - 1],
        &signature,
        ML_DSA_44
    ));
    assert!(!verify_lengths(
        &public_key,
        &signature[..signature.len() - 1],
        ML_DSA_44
    ));
}

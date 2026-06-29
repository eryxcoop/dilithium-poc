use super::*;
use crate::ml_dsa::KeyPair;
use der::Encode;

const TEST_SEED: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

#[test]
fn rfc9882_signed_attrs_roundtrip_for_all_parameter_sets() {
    for parameter_set in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        let key_pair = KeyPair::generate_from_seed(parameter_set, TEST_SEED).unwrap();
        let cms = encode_mldsa_signed_data(
            key_pair.private_key(),
            format!("RFC 9882 signed attributes for {}", parameter_set.name).as_bytes(),
            MldsaCmsSignedDataOptions::default(),
        )
        .unwrap();

        assert!(
            verify_mldsa_signed_data(key_pair.public_key(), &cms, None).unwrap(),
            "failed to verify {} CMS roundtrip",
            parameter_set.name
        );
    }
}

#[test]
fn rfc9882_without_signed_attrs_roundtrips_for_ml_dsa_44() {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let options = MldsaCmsSignedDataOptions {
        signed_attrs: CmsSignedAttrs::Absent,
        ..MldsaCmsSignedDataOptions::default()
    };

    let cms =
        encode_mldsa_signed_data(key_pair.private_key(), b"no signed attributes", options).unwrap();

    assert!(verify_mldsa_signed_data(key_pair.public_key(), &cms, None).unwrap());
}

#[test]
fn rfc9882_detached_content_roundtrips_with_signed_attrs() {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let options = MldsaCmsSignedDataOptions {
        encapsulate_content: false,
        ..MldsaCmsSignedDataOptions::default()
    };

    let cms =
        encode_mldsa_signed_data(key_pair.private_key(), b"detached payload", options).unwrap();

    assert!(
        verify_mldsa_signed_data(key_pair.public_key(), &cms, Some(b"detached payload")).unwrap()
    );
    assert_eq!(
        verify_mldsa_signed_data(key_pair.public_key(), &cms, None).unwrap_err(),
        DilithiumError::MalformedPkix("CMS content is detached")
    );
}

#[test]
fn rfc9882_tampered_content_or_wrong_key_fails_verification() {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let other_key_pair = KeyPair::generate_from_seed(ML_DSA_65, [0x22; 32]).unwrap();
    let cms = encode_mldsa_signed_data(
        key_pair.private_key(),
        b"tamper-sensitive CMS payload",
        MldsaCmsSignedDataOptions::default(),
    )
    .unwrap();

    let mut tampered = cms.clone();
    replace_first(&mut tampered, b"tamper-sensitive", b"tamper-resistent");

    assert!(!verify_mldsa_signed_data(key_pair.public_key(), &tampered, None).unwrap());
    assert!(!verify_mldsa_signed_data(other_key_pair.public_key(), &cms, None).unwrap());
}

#[test]
fn rfc9882_tampered_signed_attribute_fails_verification() {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let mut cms = encode_mldsa_signed_data(
        key_pair.private_key(),
        b"signed attribute mutation",
        MldsaCmsSignedDataOptions::default(),
    )
    .unwrap();
    let message_digest_oid = der_oid("1.2.840.113549.1.9.4");
    let index = find_subslice(&cms, &message_digest_oid).expect("messageDigest attribute present");
    cms[index + message_digest_oid.len() - 1] ^= 0x01;

    assert_eq!(
        verify_mldsa_signed_data(key_pair.public_key(), &cms, None).unwrap_err(),
        DilithiumError::MalformedPkix("signedAttrs missing message-digest")
    );
}

#[test]
fn rfc9882_digest_policy_accepts_sha256_only_for_ml_dsa_44() {
    let ml_dsa_44 = KeyPair::generate_from_seed(ML_DSA_44, TEST_SEED).unwrap();
    let ml_dsa_65 = KeyPair::generate_from_seed(ML_DSA_65, TEST_SEED).unwrap();
    let options = MldsaCmsSignedDataOptions {
        digest_algorithm: CmsDigestAlgorithm::Sha256,
        ..MldsaCmsSignedDataOptions::default()
    };

    let cms =
        encode_mldsa_signed_data(ml_dsa_44.private_key(), b"sha256 is ok here", options).unwrap();
    assert!(verify_mldsa_signed_data(ml_dsa_44.public_key(), &cms, None).unwrap());

    assert_eq!(
        encode_mldsa_signed_data(ml_dsa_65.private_key(), b"sha256 is too weak here", options)
            .unwrap_err(),
        DilithiumError::MalformedPkix("CMS digest algorithm is too weak for ML-DSA parameter set")
    );
}

#[test]
fn rfc9882_algorithm_identifiers_omit_parameters_and_reject_null() {
    let signature_alg = cms_signature_algorithm_der(ML_DSA_44).unwrap();
    let digest_alg = cms_digest_algorithm_der(CmsDigestAlgorithm::Sha512).unwrap();

    assert!(
        !signature_alg
            .windows([0x05, 0x00].len())
            .any(|w| w == [0x05, 0x00])
    );
    assert!(
        !digest_alg
            .windows([0x05, 0x00].len())
            .any(|w| w == [0x05, 0x00])
    );

    let oid = der_oid("2.16.840.1.101.3.4.3.17");
    let with_null = der_sequence(&[oid, vec![0x05, 0x00]]);
    assert_eq!(
        decode_algorithm_identifier(&with_null).unwrap_err(),
        DilithiumError::MalformedPkix("ML-DSA AlgorithmIdentifier parameters must be absent")
    );
}

#[test]
fn rfc9882_signed_attrs_helper_returns_universal_set_der() {
    let content_type = der_sequence(&[
        der_oid("1.2.840.113549.1.9.3"),
        der_set(&[der_oid("1.2.840.113549.1.7.1")]),
    ]);
    let message_digest = der_sequence(&[
        der_oid("1.2.840.113549.1.9.4"),
        der_set(&[vec![0x04, 0x01, 0xaa]]),
    ]);
    let encoded =
        cms_signed_attrs_to_be_signed_der(&[message_digest.clone(), content_type.clone()]);

    assert_eq!(encoded[0], 0x31);
    assert_eq!(encoded, der_set(&[content_type, message_digest]));
}

fn replace_first(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let start = find_subslice(haystack, needle).expect("needle present");
    haystack[start..start + needle.len()].copy_from_slice(replacement);
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn der_oid(oid: &str) -> Vec<u8> {
    der::asn1::ObjectIdentifier::new(oid)
        .unwrap()
        .to_der()
        .unwrap()
}

fn der_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    der_tag(0x30, elements)
}

fn der_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = elements.to_vec();
    sorted.sort();
    der_tag(0x31, &sorted)
}

fn der_tag(tag: u8, elements: &[Vec<u8>]) -> Vec<u8> {
    let len = elements.iter().map(Vec::len).sum::<usize>();
    let mut out = vec![tag];
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    for element in elements {
        out.extend_from_slice(element);
    }
    out
}

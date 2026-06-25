use crate::error::DilithiumError;
use crate::ml_dsa::{PrivateKey, PublicKey, keygen_from_seed};
use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use crate::pkix::{
    ConsistencyCheck, ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87, KeyUsage, PkixPrivateKey,
    algorithm_identifier_der, decode_algorithm_identifier, decode_subject_public_key_info,
    encode_one_asymmetric_key, encode_private_key_choice, parse_one_asymmetric_key,
    parse_one_asymmetric_key_with_options, parse_private_key_choice, subject_public_key_info_der,
    validate_key_usage,
};
use der::Encode;
use der::asn1::{AnyRef, BitStringRef};
use pkcs8::PrivateKeyInfo;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

#[test]
fn rfc9881_algorithm_identifier_uses_oids_without_parameters() {
    let cases = [
        (
            ML_DSA_44,
            ID_ML_DSA_44,
            vec![
                0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
            ],
        ),
        (
            ML_DSA_65,
            ID_ML_DSA_65,
            vec![
                0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
            ],
        ),
        (
            ML_DSA_87,
            ID_ML_DSA_87,
            vec![
                0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
            ],
        ),
    ];

    for (parameter_set, expected_oid, expected_der) in cases {
        let der = algorithm_identifier_der(parameter_set).unwrap();
        assert_eq!(der, expected_der);
        assert_eq!(decode_algorithm_identifier(&der).unwrap(), parameter_set);
        assert_eq!(
            expected_oid,
            crate::pkix::oid_for_parameter_set(parameter_set).unwrap()
        );
    }
}

#[test]
fn rfc9881_rejects_algorithm_identifier_parameters() {
    let with_null_parameters = [
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x05, 0x00,
    ];

    assert!(matches!(
        decode_algorithm_identifier(&with_null_parameters),
        Err(DilithiumError::MalformedPkix(_))
    ));
}

#[test]
fn rfc9881_rejects_parameters_inside_pkix_wrappers() {
    let keypair = keygen_from_seed(ML_DSA_44, [11u8; 32]).unwrap();
    let algorithm_with_null = AlgorithmIdentifierRef {
        oid: ID_ML_DSA_44,
        parameters: Some(AnyRef::NULL),
    };
    let spki_with_null = SubjectPublicKeyInfoRef {
        algorithm: algorithm_with_null,
        subject_public_key: BitStringRef::from_bytes(keypair.public_key().as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap();
    assert!(matches!(
        decode_subject_public_key_info(&spki_with_null),
        Err(DilithiumError::MalformedPkix(_))
    ));

    let choice_der = encode_private_key_choice(&PkixPrivateKey::Seed([11u8; 32])).unwrap();
    let private_key_info_with_null = PrivateKeyInfo::new(algorithm_with_null, &choice_der)
        .to_der()
        .unwrap();
    assert!(matches!(
        parse_one_asymmetric_key(&private_key_info_with_null),
        Err(DilithiumError::MalformedPkix(_))
    ));
}

#[test]
fn rfc9881_subject_public_key_info_roundtrips_raw_public_key() {
    let keypair = keygen_from_seed(ML_DSA_44, [7u8; 32]).unwrap();
    let der = subject_public_key_info_der(keypair.public_key()).unwrap();
    let decoded = decode_subject_public_key_info(&der).unwrap();

    assert_eq!(decoded, *keypair.public_key());
    assert!(der.ends_with(keypair.public_key().as_bytes()));
}

#[test]
fn rfc9881_private_key_choices_roundtrip_by_explicit_tag() {
    let keypair = keygen_from_seed(ML_DSA_44, [9u8; 32]).unwrap();
    let seed = [9u8; 32];
    let choices = [
        PkixPrivateKey::Seed(seed),
        PkixPrivateKey::Expanded(keypair.private_key().clone()),
        PkixPrivateKey::Both {
            seed,
            expanded_key: keypair.private_key().clone(),
        },
    ];

    for choice in choices {
        let der = encode_private_key_choice(&choice).unwrap();
        let decoded = parse_private_key_choice(ML_DSA_44, &der).unwrap();
        assert_eq!(decoded, choice);
    }

    let seed_der = encode_private_key_choice(&PkixPrivateKey::Seed(seed)).unwrap();
    assert_eq!(seed_der[0], 0x80);
    assert_eq!(seed_der[1], 32);
}

#[test]
fn rfc9881_one_asymmetric_key_roundtrips_seed_expanded_and_both() {
    let keypair = keygen_from_seed(ML_DSA_65, [3u8; 32]).unwrap();
    let seed = [3u8; 32];
    let choices = [
        PkixPrivateKey::Seed(seed),
        PkixPrivateKey::Expanded(keypair.private_key().clone()),
        PkixPrivateKey::Both {
            seed,
            expanded_key: keypair.private_key().clone(),
        },
    ];

    for choice in choices {
        let der =
            encode_one_asymmetric_key(ML_DSA_65, &choice, Some(keypair.public_key())).unwrap();
        let decoded = parse_one_asymmetric_key(&der).unwrap();
        assert_eq!(decoded.parameter_set(), ML_DSA_65);
        assert_eq!(decoded.private_key(), &choice);
        assert_eq!(decoded.public_key(), Some(keypair.public_key()));
    }
}

#[test]
fn rfc9881_rejects_inconsistent_both_private_key_by_default() {
    let keypair = keygen_from_seed(ML_DSA_44, [4u8; 32]).unwrap();
    let inconsistent = PkixPrivateKey::Both {
        seed: [5u8; 32],
        expanded_key: keypair.private_key().clone(),
    };
    let der = encode_one_asymmetric_key(ML_DSA_44, &inconsistent, None).unwrap();

    assert!(matches!(
        parse_one_asymmetric_key(&der),
        Err(DilithiumError::InconsistentPrivateKey(_))
    ));
    assert!(parse_one_asymmetric_key_with_options(&der, ConsistencyCheck::Skip).is_ok());
}

#[test]
fn rfc9881_rejects_key_usage_without_allowed_bits_or_with_forbidden_bits() {
    assert!(
        validate_key_usage(KeyUsage {
            digital_signature: true,
            ..KeyUsage::default()
        })
        .is_ok()
    );
    assert!(
        validate_key_usage(KeyUsage {
            key_cert_sign: true,
            crl_sign: true,
            ..KeyUsage::default()
        })
        .is_ok()
    );

    assert!(matches!(
        validate_key_usage(KeyUsage::default()),
        Err(DilithiumError::InvalidKeyUsage(_))
    ));
    assert!(matches!(
        validate_key_usage(KeyUsage {
            digital_signature: true,
            key_agreement: true,
            ..KeyUsage::default()
        }),
        Err(DilithiumError::InvalidKeyUsage(_))
    ));
}

#[test]
fn rfc9881_rejects_mismatched_raw_key_lengths() {
    let wrong_public_key =
        PublicKey::from_raw(ML_DSA_44, vec![0u8; ML_DSA_44.sizes.public_key_bytes]).unwrap();
    let wrong_spki = subject_public_key_info_der(&wrong_public_key).unwrap();
    assert!(decode_subject_public_key_info(&wrong_spki).is_ok());

    let wrong_private_key =
        PrivateKey::from_raw(ML_DSA_44, vec![0u8; ML_DSA_44.sizes.private_key_bytes]).unwrap();
    let expanded_der =
        encode_private_key_choice(&PkixPrivateKey::Expanded(wrong_private_key)).unwrap();
    assert!(matches!(
        parse_private_key_choice(ML_DSA_87, &expanded_der),
        Err(DilithiumError::InvalidLength { .. })
    ));
}

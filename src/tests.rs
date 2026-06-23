use crate::coefficient::{CANONICAL_MAX, CANONICAL_MIN, CENTERED_MAX, CENTERED_MIN, Coefficient};
use crate::encoding::{
    bit_pack, bit_unpack, bits_to_bytes, bits_to_integer, bytes_to_bits, hint_bit_pack,
    hint_bit_unpack, integer_to_bytes, pk_decode, pk_encode, simple_bit_pack, simple_bit_unpack,
    sk_decode, sk_encode,
};
use crate::error::DilithiumError;
use crate::hints::HintsVector;
use crate::params::{
    CoreParams, D, EncodedSizes, ML_DSA_44, ML_DSA_65, ML_DSA_87, N, PARAMETER_SETS, ParameterSet,
    ParameterSetId, Q, ZETA,
};
use crate::poly::{NttPoly, Poly, PolyMatrix, PolyVector};

#[test]
fn crate_scaffold_is_ready() {
    assert_eq!(env!("CARGO_PKG_NAME"), "dilithium-poc");
}

#[test]
fn fips_parameter_sets_are_exposed() {
    assert_eq!(ML_DSA_44.sizes.public_key_bytes, 1312);
    assert_eq!(ML_DSA_65.sizes.private_key_bytes, 4032);
    assert_eq!(ML_DSA_87.sizes.signature_bytes, 4627);
}

#[test]
fn core_params_are_grouped() {
    assert_eq!(ML_DSA_44.core.k, 4);
    assert_eq!(ML_DSA_65.core.gamma1, 1 << 19);
    assert_eq!(ML_DSA_87.core.omega, 75);
}

#[test]
fn fips_global_constants_match_spec() {
    assert_eq!(N, 256);
    assert_eq!(Q, 8_380_417);
    assert_eq!(ZETA, 1_753);
    assert_eq!(D, 13);
}

#[test]
fn all_fips_parameter_sets_match_expected_values() {
    assert_eq!(ML_DSA_44.core.k, 4);
    assert_eq!(ML_DSA_44.core.l, 4);
    assert_eq!(ML_DSA_44.core.eta, 2);
    assert_eq!(ML_DSA_44.core.tau, 39);
    assert_eq!(ML_DSA_44.core.lambda, 128);
    assert_eq!(ML_DSA_44.core.gamma1, 1 << 17);
    assert_eq!(ML_DSA_44.core.gamma2, (Q - 1) / 88);
    assert_eq!(ML_DSA_44.core.beta, 78);
    assert_eq!(ML_DSA_44.core.omega, 80);

    assert_eq!(ML_DSA_65.core.k, 6);
    assert_eq!(ML_DSA_65.core.l, 5);
    assert_eq!(ML_DSA_65.core.eta, 4);
    assert_eq!(ML_DSA_65.core.tau, 49);
    assert_eq!(ML_DSA_65.core.lambda, 192);
    assert_eq!(ML_DSA_65.core.gamma1, 1 << 19);
    assert_eq!(ML_DSA_65.core.gamma2, (Q - 1) / 32);
    assert_eq!(ML_DSA_65.core.beta, 196);
    assert_eq!(ML_DSA_65.core.omega, 55);

    assert_eq!(ML_DSA_87.core.k, 8);
    assert_eq!(ML_DSA_87.core.l, 7);
    assert_eq!(ML_DSA_87.core.eta, 2);
    assert_eq!(ML_DSA_87.core.tau, 60);
    assert_eq!(ML_DSA_87.core.lambda, 256);
    assert_eq!(ML_DSA_87.core.gamma1, 1 << 19);
    assert_eq!(ML_DSA_87.core.gamma2, (Q - 1) / 32);
    assert_eq!(ML_DSA_87.core.beta, 120);
    assert_eq!(ML_DSA_87.core.omega, 75);
}

#[test]
fn size_tables_match_fips_formulas() {
    for parameter_set in PARAMETER_SETS {
        assert_eq!(
            parameter_set.sizes.public_key_bytes,
            parameter_set.derived_public_key_bytes()
        );
        assert_eq!(
            parameter_set.sizes.private_key_bytes,
            parameter_set.derived_private_key_bytes()
        );
        assert_eq!(
            parameter_set.sizes.signature_bytes,
            parameter_set.derived_signature_bytes()
        );
        assert!(parameter_set.has_consistent_sizes());
    }
}

#[test]
fn polynomial_domain_types_follow_parameter_dimensions() {
    let poly = Poly::zero();
    assert_eq!(poly.coeffs().len(), N);
    assert_eq!(poly.coeff(0), Some(Coefficient::default()));

    let vector_l = PolyVector::zero_l(ML_DSA_44);
    assert_eq!(vector_l.dimension(), ML_DSA_44.core.l);
    assert_eq!(vector_l.get(0), Some(&Poly::zero()));

    let vector_k = PolyVector::zero_k(ML_DSA_65);
    assert_eq!(vector_k.dimension(), ML_DSA_65.core.k);
    assert!(!vector_k.is_empty());

    let matrix = PolyMatrix::zero_kl(ML_DSA_87);
    assert_eq!(matrix.rows(), ML_DSA_87.core.k);
    assert_eq!(matrix.cols(), ML_DSA_87.core.l);
    assert_eq!(matrix.shape(), (ML_DSA_87.core.k, ML_DSA_87.core.l));
    assert_eq!(matrix.polys().len(), ML_DSA_87.core.k * ML_DSA_87.core.l);
    assert_eq!(matrix.get(0, 0), Some(&Poly::zero()));
    assert_eq!(matrix.row(0).map(|row| row.len()), Some(ML_DSA_87.core.l));
}

#[test]
fn polynomial_domain_types_reject_wrong_lengths() {
    let err = PolyVector::from_polys(2, vec![Poly::zero()]).unwrap_err();
    assert_eq!(
        err,
        DilithiumError::InvalidLength {
            expected: 2,
            actual: 1,
            item: "polynomial vector",
        }
    );

    let err = PolyMatrix::from_polys(2, 3, vec![Poly::zero(); 5]).unwrap_err();
    assert_eq!(
        err,
        DilithiumError::InvalidLength {
            expected: 6,
            actual: 5,
            item: "polynomial matrix",
        }
    );
}

#[cfg(any(test, feature = "experimental-params"))]
#[test]
fn experimental_parameter_sets_are_available_only_for_non_standard_work() {
    let experimental = ParameterSet::new_experimental(
        "EXP-ML-DSA",
        0,
        CoreParams {
            k: 1,
            l: 2,
            eta: 3,
            tau: 4,
            lambda: 128,
            gamma1: 1 << 10,
            gamma2: 32,
            beta: 12,
            omega: 5,
        },
        EncodedSizes {
            public_key_bytes: 64,
            private_key_bytes: 96,
            signature_bytes: 128,
        },
    );

    #[cfg(any(test, feature = "experimental-params"))]
    assert_eq!(experimental.id, ParameterSetId::Experimental);
    assert_eq!(experimental.name, "EXP-ML-DSA");
    assert_eq!(experimental.core.k, 1);
    assert_eq!(experimental.sizes.signature_bytes, 128);
}

#[test]
fn canonical_reduction_returns_values_in_expected_range() {
    assert_eq!(Coefficient::canonical(0), Coefficient::canonical(0));
    assert_eq!(Coefficient::canonical(Q as i64), Coefficient::canonical(0));
    assert_eq!(Coefficient::canonical(-1), Coefficient::canonical(-1));
    assert_eq!(
        Coefficient::canonical((Q as i64) + 7),
        Coefficient::canonical(7)
    );

    assert!(Coefficient::canonical(-123_456_789).is_canonical());
    assert_eq!(CANONICAL_MIN.value(), 0);
    assert_eq!(CANONICAL_MAX.value(), Q as i32 - 1);
}

#[test]
fn centered_reduction_returns_symmetric_representatives() {
    assert_eq!(Coefficient::centered(0), Coefficient::centered(0));
    assert_eq!(Coefficient::centered(-1), Coefficient::centered(-1));
    assert_eq!(
        Coefficient::centered(Q as i64 - 1),
        Coefficient::centered(-1)
    );
    assert_eq!(Coefficient::centered((Q as i64 + 1) / 2), CENTERED_MIN);
    assert_eq!(CENTERED_MIN.value(), -CENTERED_MAX.value());

    assert!(Coefficient::centered(123_456_789).is_centered());
    assert!(Coefficient::centered(-123_456_789).is_centered());
}

#[test]
fn modular_add_sub_and_neg_preserve_congruence() {
    assert_eq!(
        Coefficient::from(Q as i32 - 1) + Coefficient::from(2),
        Coefficient::from(1)
    );
    assert_eq!(
        Coefficient::from(1) - Coefficient::from(2),
        Coefficient::from(Q as i32 - 1)
    );
    assert_eq!(-Coefficient::from(0), Coefficient::from(0));
    assert_eq!(-Coefficient::from(1), Coefficient::from(Q as i32 - 1));
    assert_eq!(
        -Coefficient::from(123) + Coefficient::from(123),
        Coefficient::from(0)
    );
}

#[test]
fn coefficient_operator_overloads_use_modular_arithmetic() {
    let lhs = Coefficient::from(Q as i32 - 1);
    let rhs = Coefficient::from(2);

    assert_eq!(lhs + rhs, Coefficient::from(1));
    assert_eq!(Coefficient::from(1) - rhs, Coefficient::from(Q as i32 - 1));
    assert_eq!(-Coefficient::from(1), Coefficient::from(Q as i32 - 1));
}

#[test]
fn polynomial_operator_overloads_are_coefficientwise() {
    let lhs = Poly::from_coeffs([Coefficient::from(1); N]);
    let rhs = Poly::from_coeffs([Coefficient::from(2); N]);

    let sum = &lhs + &rhs;
    let diff = &rhs - &lhs;
    let neg = -&lhs;

    assert!(sum.iter().all(|coeff| coeff == Coefficient::from(3)));
    assert!(diff.iter().all(|coeff| coeff == Coefficient::from(1)));
    assert!(
        neg.iter()
            .all(|coeff| coeff == Coefficient::from(Q as i32 - 1))
    );
}

#[test]
fn polynomial_vectors_support_checked_shape_aware_arithmetic() {
    let lhs = PolyVector::from_polys(2, vec![Poly::zero(), Poly::zero()]).unwrap();
    let rhs = PolyVector::from_polys(2, vec![Poly::zero(), Poly::zero()]).unwrap();
    let mismatch = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();

    let sum = lhs.checked_add(&rhs).unwrap();
    let diff = lhs.checked_sub(&rhs).unwrap();
    let neg = rhs.neg();

    assert_eq!(sum.dimension(), 2);
    assert_eq!(diff.dimension(), 2);
    assert_eq!(neg.dimension(), 2);
    assert_eq!(
        lhs.checked_add(&mismatch).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: 2,
            actual: 1,
            item: "polynomial vector dimension",
        }
    );
}

#[test]
fn polynomial_matrix_accessors_respect_shape() {
    let matrix = PolyMatrix::from_polys(2, 2, vec![Poly::zero(); 4]).unwrap();

    assert_eq!(matrix.get(1, 1), Some(&Poly::zero()));
    assert_eq!(matrix.get(2, 0), None);
    assert_eq!(matrix.row(1).map(|row| row.len()), Some(2));
    assert_eq!(matrix.row(2), None);
    assert_eq!(matrix.rows_iter().count(), 2);
}

#[test]
fn ntt_roundtrip_restores_polynomial() {
    let mut coeffs = [Coefficient::default(); N];
    coeffs[0] = Coefficient::from(1);
    coeffs[1] = Coefficient::from(2);
    coeffs[17] = Coefficient::from(1234);
    coeffs[255] = Coefficient::from(Q as i32 - 7);

    let poly = Poly::from_coeffs(coeffs);
    let transformed = poly.ntt();
    let restored = transformed.inverse_ntt();

    assert_eq!(restored, poly);
}

#[test]
fn ntt_pointwise_multiplication_matches_negacyclic_product() {
    let mut lhs_coeffs = [Coefficient::default(); N];
    lhs_coeffs[0] = Coefficient::from(3);
    lhs_coeffs[1] = Coefficient::from(5);
    lhs_coeffs[4] = Coefficient::from(7);
    lhs_coeffs[9] = Coefficient::from(11);

    let mut rhs_coeffs = [Coefficient::default(); N];
    rhs_coeffs[0] = Coefficient::from(2);
    rhs_coeffs[2] = Coefficient::from(13);
    rhs_coeffs[3] = Coefficient::from(17);
    rhs_coeffs[8] = Coefficient::from(19);

    let lhs = Poly::from_coeffs(lhs_coeffs);
    let rhs = Poly::from_coeffs(rhs_coeffs);

    let lhs_ntt = lhs.ntt();
    let rhs_ntt = rhs.ntt();
    let product_ntt = (&lhs_ntt * &rhs_ntt).inverse_ntt();
    let product_naive = naive_negacyclic_mul(&lhs, &rhs);

    assert_eq!(product_ntt, product_naive);
}

#[test]
fn ntt_domain_supports_accessors_and_pointwise_arithmetic() {
    let zero = NttPoly::zero();
    assert_eq!(zero.coeff(0), Some(Coefficient::default()));

    let lhs = NttPoly::from_coeffs([Coefficient::from(1); N]);
    let rhs = NttPoly::from_coeffs([Coefficient::from(2); N]);
    let sum = &lhs + &rhs;
    let product = &lhs * &rhs;

    assert!(sum.iter().all(|coeff| coeff == Coefficient::from(3)));
    assert!(product.iter().all(|coeff| coeff == Coefficient::from(2)));
}

#[test]
fn power2_round_recombines_coefficients_mod_q() {
    let modulus = 1i64 << D;
    let samples = [
        0,
        1,
        -1,
        (modulus / 2) - 1,
        modulus / 2,
        modulus - 1,
        modulus,
        (Q as i64) - 1,
        Q as i64,
        (Q as i64) + 1,
    ];

    for sample in samples {
        let coefficient = Coefficient::canonical(sample);
        let rounded = coefficient.power2_round();
        let recombined =
            Coefficient::canonical((rounded.high() as i64 * modulus) + (rounded.low() as i64));

        assert_eq!(recombined, coefficient);
        assert!(rounded.low() > -((modulus / 2) as i32));
        assert!(rounded.low() <= (modulus / 2) as i32);
    }
}

#[test]
fn decompose_recombines_coefficients_for_all_fips_gamma2_values() {
    let samples = [
        0,
        1,
        -1,
        (Q as i64 / 7) - 3,
        (Q as i64 / 5) + 9,
        (Q as i64) - 2,
        (Q as i64) - 1,
        Q as i64,
        (Q as i64) + 17,
    ];

    for parameter_set in PARAMETER_SETS {
        let alpha = 2 * parameter_set.core.gamma2 as i64;

        for sample in samples {
            let coefficient = Coefficient::canonical(sample);
            let decomposed = coefficient.decompose(parameter_set.core.gamma2);
            let recombined = Coefficient::canonical(
                (decomposed.high() as i64 * alpha) + (decomposed.low() as i64),
            );

            assert_eq!(recombined, coefficient);
            assert!(decomposed.low() >= -(parameter_set.core.gamma2 as i32));
            assert!(decomposed.low() <= parameter_set.core.gamma2 as i32);
        }
    }
}

#[test]
fn decompose_applies_the_fips_wraparound_rule_at_q_minus_one() {
    let coefficient = Coefficient::from(Q as i32 - 1);

    for parameter_set in PARAMETER_SETS {
        let decomposed = coefficient.decompose(parameter_set.core.gamma2);

        assert_eq!(decomposed.high(), 0);
        assert_eq!(decomposed.low(), -1);
    }
}

#[test]
fn high_bits_and_low_bits_match_decompose_output() {
    let coefficient = Coefficient::canonical((Q as i64 / 3) + 11);

    for parameter_set in PARAMETER_SETS {
        let decomposed = coefficient.decompose(parameter_set.core.gamma2);

        assert_eq!(
            coefficient.high_bits(parameter_set.core.gamma2),
            decomposed.high()
        );
        assert_eq!(
            coefficient.low_bits(parameter_set.core.gamma2),
            decomposed.low()
        );
    }
}

#[test]
fn make_hint_detects_high_bit_changes() {
    let gamma2 = ML_DSA_44.core.gamma2;
    let stable = Coefficient::from(5);
    let changes = Coefficient::from(gamma2 as i32);

    assert!(!stable.make_hint(Coefficient::from(3), gamma2));
    assert!(changes.make_hint(Coefficient::from(1), gamma2));
}

#[test]
fn use_hint_applies_fips_increment_and_decrement_rules() {
    let gamma2 = ML_DSA_44.core.gamma2;
    let m = (Q - 1) / (2 * gamma2);

    assert_eq!(Coefficient::from(gamma2 as i32).use_hint(true, gamma2), 1);
    assert_eq!(Coefficient::from(0).use_hint(true, gamma2), m - 1);
    assert_eq!(
        Coefficient::from(gamma2 as i32).use_hint(false, gamma2),
        Coefficient::from(gamma2 as i32).high_bits(gamma2)
    );
}

#[test]
fn make_hint_and_use_hint_vectors_roundtrip_through_hint_encoding() {
    let gamma2 = ML_DSA_44.core.gamma2;
    let z = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 1)]),
            poly_with_coefficients(&[(1, 3)]),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();
    let r = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, gamma2 as i32)]),
            poly_with_coefficients(&[(1, 5)]),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    let hints = HintsVector::make(ML_DSA_44, &z, &r).unwrap();
    let packed = hint_bit_pack(&hints).unwrap();
    let unpacked = hint_bit_unpack(&packed, ML_DSA_44).unwrap();
    let adjusted = unpacked.use_on(&r).unwrap();
    let expected = high_bits_vector(&r.checked_add(&z).unwrap(), gamma2);

    assert_eq!(unpacked, hints);
    assert_eq!(adjusted, expected);
}

#[test]
fn hints_vector_rejects_non_binary_hints() {
    let hints = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 2)]),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_44, hints).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "hint coefficient",
            min: 0,
            max: 1,
            actual: 2,
        }
    );
}

#[test]
fn bits_to_integer_uses_little_endian_bit_order() {
    assert_eq!(bits_to_integer(&[1, 0, 1, 1]).unwrap(), 13);
    assert_eq!(bits_to_integer(&[0, 1, 0, 1, 1]).unwrap(), 26);
}

#[test]
fn integer_to_bytes_uses_little_endian_byte_order() {
    assert_eq!(
        integer_to_bytes(0x12_34_56, 4),
        vec![0x56, 0x34, 0x12, 0x00]
    );
    assert_eq!(integer_to_bytes(257, 2), vec![1, 1]);
}

#[test]
fn bits_and_bytes_roundtrip() {
    let bytes = vec![0xa5, 0x01, 0xfe];
    let bits = bytes_to_bits(&bytes);

    assert_eq!(bits_to_bytes(&bits).unwrap(), bytes);
}

#[test]
fn simple_bit_pack_and_unpack_roundtrip() {
    let mut values = [Coefficient::default(); N];
    values[0] = Coefficient::from(0);
    values[1] = Coefficient::from(3);
    values[2] = Coefficient::from(7);
    values[3] = Coefficient::from(1);
    values[4] = Coefficient::from(4);
    values[5] = Coefficient::from(2);
    let poly = Poly::from_coeffs(values);

    let packed = simple_bit_pack(&poly, 7).unwrap();
    let unpacked = simple_bit_unpack(&packed, 7).unwrap();

    assert_eq!(unpacked, Poly::from_coeffs(values));
}

#[test]
fn bit_pack_and_unpack_roundtrip() {
    let mut values = [Coefficient::default(); N];
    values[0] = Coefficient::from(0);
    values[1] = Coefficient::from((Q - 2) as i32);
    values[2] = Coefficient::from(2);
    values[3] = Coefficient::from((Q - 1) as i32);
    values[4] = Coefficient::from(1);
    values[5] = Coefficient::from(2);
    let poly = Poly::from_coeffs(values);

    let packed = bit_pack(&poly, 2, 2).unwrap();
    let unpacked = bit_unpack(&packed, 2, 2).unwrap();

    assert_eq!(unpacked, Poly::from_coeffs(values));
}

#[test]
fn bits_to_bytes_rejects_non_binary_input() {
    assert_eq!(
        bits_to_bytes(&[0, 1, 2]).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "bit",
            min: 0,
            max: 1,
            actual: 2,
        }
    );
}

#[test]
fn simple_bit_unpack_rejects_malformed_out_of_range_coefficients() {
    let malformed = vec![0x0f; 128];

    assert_eq!(
        simple_bit_unpack(&malformed, 10).unwrap_err(),
        DilithiumError::MalformedEncoding("simple bit unpack produced out-of-range coefficient")
    );
}

#[test]
fn bit_unpack_rejects_malformed_out_of_range_coefficients() {
    let malformed = vec![0x0f; 96];

    assert_eq!(
        bit_unpack(&malformed, 2, 2).unwrap_err(),
        DilithiumError::MalformedEncoding("bit unpack produced out-of-range coefficient")
    );
}

#[test]
fn unpack_rejects_wrong_lengths() {
    assert_eq!(
        simple_bit_unpack(&[], 7).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 96,
            actual: 0,
            item: "simple bit packed polynomial",
        }
    );
    assert_eq!(
        bit_unpack(&[], 2, 2).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 96,
            actual: 0,
            item: "bit packed polynomial",
        }
    );
}

#[test]
fn hint_bit_pack_and_unpack_roundtrip() {
    let hints = HintsVector::new(
        ML_DSA_44,
        PolyVector::from_polys(
            ML_DSA_44.core.k,
            vec![
                binary_hint_poly(&[0, 7]),
                binary_hint_poly(&[3]),
                binary_hint_poly(&[]),
                binary_hint_poly(&[255]),
            ],
        )
        .unwrap(),
    )
    .unwrap();

    let packed = hint_bit_pack(&hints).unwrap();
    let unpacked = hint_bit_unpack(&packed, ML_DSA_44).unwrap();

    assert_eq!(
        packed.len(),
        ML_DSA_44.core.omega as usize + ML_DSA_44.core.k
    );
    assert_eq!(packed[0..4], [0, 7, 3, 255]);
    assert_eq!(packed[80..84], [2, 3, 3, 4]);
    assert_eq!(unpacked, hints);
}

#[test]
fn hints_vector_rejects_wrong_dimension() {
    let hints = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_44, hints).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.k,
            actual: 1,
            item: "hint vector dimension",
        }
    );
}

#[test]
fn hints_vector_rejects_non_binary_coefficients() {
    let hints = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            Poly::from_coeffs({
                let mut coeffs = [Coefficient::default(); N];
                coeffs[0] = Coefficient::from(2);
                coeffs
            }),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_44, hints).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "hint coefficient",
            min: 0,
            max: 1,
            actual: 2,
        }
    );
}

#[test]
fn hints_vector_rejects_weight_above_omega() {
    let hints = PolyVector::from_polys(
        ML_DSA_65.core.k,
        vec![
            binary_hint_poly(&(0..=ML_DSA_65.core.omega as usize).collect::<Vec<_>>()),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_65, hints).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "hint weight",
            min: 0,
            max: ML_DSA_65.core.omega as i64,
            actual: ML_DSA_65.core.omega as i64 + 1,
        }
    );
}

#[test]
fn hint_bit_unpack_rejects_wrong_length() {
    assert_eq!(
        hint_bit_unpack(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.core.omega as usize + ML_DSA_44.core.k,
            actual: 0,
            item: "hint encoding",
        }
    );
}

#[test]
fn hint_bit_unpack_rejects_non_monotonic_boundaries() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 0;
    malformed[1] = 1;
    malformed[80] = 2;
    malformed[81] = 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint boundary is not monotonic or exceeds omega")
    );
}

#[test]
fn hint_bit_unpack_rejects_boundaries_above_omega() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[80] = ML_DSA_44.core.omega as u8 + 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint boundary is not monotonic or exceeds omega")
    );
}

#[test]
fn hint_bit_unpack_rejects_duplicate_or_descending_indices() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 7;
    malformed[1] = 7;
    malformed[80] = 2;
    malformed[81] = 2;
    malformed[82] = 2;
    malformed[83] = 2;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint indices are not strictly increasing")
    );
}

#[test]
fn hint_bit_unpack_rejects_nonzero_leftover_index_bytes() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("unused hint index byte is nonzero")
    );
}

#[test]
fn public_key_encode_and_decode_roundtrip() {
    let rho = [7u8; 32];
    let t1 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 0), (1, 1023)]),
            poly_with_coefficients(&[(2, 17)]),
            poly_with_coefficients(&[(3, 511)]),
            poly_with_coefficients(&[(4, 999)]),
        ],
    )
    .unwrap();

    let encoded = pk_encode(rho, &t1, ML_DSA_44).unwrap();
    let decoded = pk_decode(&encoded, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), ML_DSA_44.sizes.public_key_bytes);
    assert_eq!(decoded.rho, rho);
    assert_eq!(decoded.t1, t1);
}

#[test]
fn public_key_encode_rejects_wrong_t1_dimension() {
    let t1 = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();

    assert_eq!(
        pk_encode([0u8; 32], &t1, ML_DSA_44).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.k,
            actual: 1,
            item: "public key t1 vector",
        }
    );
}

#[test]
fn public_key_encode_rejects_out_of_range_t1_coefficients() {
    let t1 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 1024)]),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        pk_encode([0u8; 32], &t1, ML_DSA_44).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "packed coefficient",
            min: 0,
            max: 1023,
            actual: 1024,
        }
    );
}

#[test]
fn public_key_decode_rejects_wrong_length() {
    assert_eq!(
        pk_decode(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.sizes.public_key_bytes,
            actual: 0,
            item: "public key",
        }
    );
}

#[test]
fn private_key_encode_and_decode_roundtrip() {
    let rho = [1u8; 32];
    let secret_key_seed = [2u8; 32];
    let tr = [3u8; 64];
    let s1 = PolyVector::from_polys(
        ML_DSA_44.core.l,
        vec![
            poly_with_coefficients(&[(0, -2), (1, 2)]),
            poly_with_coefficients(&[(2, -1)]),
            poly_with_coefficients(&[(3, 1)]),
            Poly::zero(),
        ],
    )
    .unwrap();
    let s2 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(4, 2)]),
            poly_with_coefficients(&[(5, -2)]),
            Poly::zero(),
            poly_with_coefficients(&[(6, 1)]),
        ],
    )
    .unwrap();
    let t0 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, -4095), (1, 4096)]),
            poly_with_coefficients(&[(2, -1)]),
            poly_with_coefficients(&[(3, 1)]),
            Poly::zero(),
        ],
    )
    .unwrap();

    let encoded = sk_encode(rho, secret_key_seed, tr, &s1, &s2, &t0, ML_DSA_44).unwrap();
    let decoded = sk_decode(&encoded, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), ML_DSA_44.sizes.private_key_bytes);
    assert_eq!(decoded.rho, rho);
    assert_eq!(decoded.secret_key_seed, secret_key_seed);
    assert_eq!(decoded.tr, tr);
    assert_eq!(decoded.s1, s1);
    assert_eq!(decoded.s2, s2);
    assert_eq!(decoded.t0, t0);
}

#[test]
fn private_key_encode_rejects_wrong_dimensions() {
    let wrong_s1 = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();
    let s2 = PolyVector::zero_k(ML_DSA_44);
    let t0 = PolyVector::zero_k(ML_DSA_44);

    assert_eq!(
        sk_encode(
            [0u8; 32], [0u8; 32], [0u8; 64], &wrong_s1, &s2, &t0, ML_DSA_44,
        )
        .unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.l,
            actual: 1,
            item: "private key s1 vector",
        }
    );
}

#[test]
fn private_key_decode_rejects_wrong_length() {
    assert_eq!(
        sk_decode(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.sizes.private_key_bytes,
            actual: 0,
            item: "private key",
        }
    );
}

#[test]
fn private_key_decode_rejects_malformed_secret_polynomial() {
    let s1 = PolyVector::zero_l(ML_DSA_44);
    let s2 = PolyVector::zero_k(ML_DSA_44);
    let t0 = PolyVector::zero_k(ML_DSA_44);
    let mut encoded = sk_encode([0u8; 32], [0u8; 32], [0u8; 64], &s1, &s2, &t0, ML_DSA_44).unwrap();

    encoded[128] = 0b0000_0111;

    assert_eq!(
        sk_decode(&encoded, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("bit unpack produced out-of-range coefficient")
    );
}

fn naive_negacyclic_mul(lhs: &Poly, rhs: &Poly) -> Poly {
    let mut accum = [0i64; N];

    for (i, lhs_coeff) in lhs.iter().enumerate() {
        for (j, rhs_coeff) in rhs.iter().enumerate() {
            let product = (lhs_coeff.value() as i64) * (rhs_coeff.value() as i64);
            let index = (i + j) % N;
            if i + j < N {
                accum[index] += product;
            } else {
                accum[index] -= product;
            }
        }
    }

    Poly::from_coeffs(core::array::from_fn(|index| {
        Coefficient::canonical(accum[index])
    }))
}

fn binary_hint_poly(indices: &[usize]) -> Poly {
    let mut coeffs = [Coefficient::default(); N];
    for &index in indices {
        coeffs[index] = Coefficient::from(1);
    }
    Poly::from_coeffs(coeffs)
}

fn poly_with_coefficients(entries: &[(usize, i32)]) -> Poly {
    let mut coeffs = [Coefficient::default(); N];
    for &(index, value) in entries {
        coeffs[index] = Coefficient::from(value);
    }
    Poly::from_coeffs(coeffs)
}

fn high_bits_vector(vector: &PolyVector, gamma2: u32) -> PolyVector {
    PolyVector::from_polys(
        vector.dimension(),
        vector
            .iter()
            .map(|poly| {
                Poly::from_coeffs(core::array::from_fn(|index| {
                    Coefficient::from(
                        poly.coeff(index)
                            .expect("coefficient index is in range")
                            .high_bits(gamma2) as i32,
                    )
                }))
            })
            .collect(),
    )
    .unwrap()
}

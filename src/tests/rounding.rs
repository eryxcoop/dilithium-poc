use super::*;

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

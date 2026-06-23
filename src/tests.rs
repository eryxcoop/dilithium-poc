use super::*;

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
        Error::InvalidLength {
            expected: 2,
            actual: 1,
            item: "polynomial vector",
        }
    );

    let err = PolyMatrix::from_polys(2, 3, vec![Poly::zero(); 5]).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidLength {
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

    let sum = lhs.clone() + rhs.clone();
    let diff = rhs - lhs.clone();
    let neg = -lhs;

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
        Error::DimensionMismatch {
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

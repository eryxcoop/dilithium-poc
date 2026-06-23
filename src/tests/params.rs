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

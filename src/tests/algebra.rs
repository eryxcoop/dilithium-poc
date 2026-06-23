use super::*;

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

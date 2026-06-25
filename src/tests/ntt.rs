use super::*;

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
fn ntt_poly_vector_tracks_dimension_and_inverse_transform() {
    let first = poly_with_coefficients(&[(0, 1), (5, 42)]);
    let second = poly_with_coefficients(&[(1, 7), (255, Q as i32 - 3)]);
    let vector = NttPolyVector::from_polys(2, vec![first.ntt(), second.ntt()]).unwrap();

    assert_eq!(vector.dimension(), 2);
    assert!(!vector.is_empty());
    assert_eq!(vector.iter().len(), 2);
    assert!(vector.get(1).is_some());

    let restored = vector.inverse_ntt().unwrap();
    assert_eq!(restored.dimension(), 2);
    assert_eq!(restored.get(0), Some(&first));
    assert_eq!(restored.get(1), Some(&second));
}

#[test]
fn ntt_poly_vector_rejects_wrong_dimension() {
    let error = NttPolyVector::from_polys(2, vec![NttPoly::zero()]).unwrap_err();

    assert_eq!(
        error,
        DilithiumError::InvalidLength {
            expected: 2,
            actual: 1,
            item: "NTT polynomial vector",
        }
    );
}

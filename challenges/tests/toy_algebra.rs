use dilithium_poc_challenges::toy::{ToyAlgebraError, ToyParams, ToyPoly, ToyVector};

#[test]
fn toy_params_validate_degree_and_modulus() {
    assert_eq!(ToyParams::new(0, 17), Err(ToyAlgebraError::ZeroDegree));
    assert_eq!(ToyParams::new(4, 1), Err(ToyAlgebraError::InvalidModulus));
    assert!(ToyParams::new(4, 17).is_ok());
}

#[test]
fn toy_poly_reduces_and_centers_coefficients() {
    let params = ToyParams::new(4, 17).unwrap();
    let poly = ToyPoly::from_coeffs(params, vec![0, 16, 17, -2]).unwrap();

    assert_eq!(poly.coeffs(), &[0, 16, 0, 15]);
    assert_eq!(poly.centered_coeffs(), vec![0, -1, 0, -2]);
    assert_eq!(poly.infinity_norm(), 2);
}

#[test]
fn toy_poly_multiplies_mod_xn_plus_one() {
    let params = ToyParams::new(4, 17).unwrap();
    let x = ToyPoly::from_coeffs(params, vec![0, 1, 0, 0]).unwrap();
    let x_cubed = ToyPoly::from_coeffs(params, vec![0, 0, 0, 1]).unwrap();

    let product = x.checked_mul(&x_cubed).unwrap();

    assert_eq!(product.centered_coeffs(), vec![-1, 0, 0, 0]);
}

#[test]
fn toy_operations_reject_parameter_mismatches() {
    let lhs_params = ToyParams::new(4, 17).unwrap();
    let rhs_params = ToyParams::new(4, 19).unwrap();
    let lhs = ToyPoly::zero(lhs_params);
    let rhs = ToyPoly::zero(rhs_params);

    assert_eq!(
        lhs.checked_add(&rhs),
        Err(ToyAlgebraError::ParameterMismatch)
    );
}

#[test]
fn toy_vector_tracks_dimension_and_norm() {
    let params = ToyParams::new(4, 17).unwrap();
    let first = ToyPoly::from_coeffs(params, vec![1, -2, 0, 0]).unwrap();
    let second = ToyPoly::from_coeffs(params, vec![0, 0, 8, 0]).unwrap();
    let vector = ToyVector::from_polys(params, vec![first, second]).unwrap();

    assert_eq!(vector.dimension(), 2);
    assert_eq!(vector.infinity_norm(), 8);
}

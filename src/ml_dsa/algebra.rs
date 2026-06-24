//! Algebraic helpers used by the high-level ML-DSA algorithms.

use crate::coefficient::Coefficient;
use crate::error::DilithiumResult;
use crate::params::{D, N, ParameterSet};
use crate::poly::{NttMatrix, NttPoly, Poly, PolyVector};
use crate::validation::ensure_dimension;

pub(crate) fn ntt_vector(vector: &PolyVector) -> Vec<NttPoly> {
    vector.iter().map(Poly::ntt).collect()
}

pub(crate) fn multiply_ntt_matrix_vector(
    matrix: &NttMatrix,
    vector: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    let vector_hat = ntt_vector(vector);
    multiply_ntt_matrix_ntt_vector(matrix, &vector_hat, parameter_set)
}

pub(crate) fn multiply_ntt_matrix_ntt_vector(
    matrix: &NttMatrix,
    vector_hat: &[NttPoly],
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    ensure_dimension("NTT matrix rows", parameter_set.core.k, matrix.rows())?;
    ensure_dimension("NTT matrix columns", parameter_set.core.l, matrix.cols())?;
    ensure_dimension(
        "NTT vector dimension",
        parameter_set.core.l,
        vector_hat.len(),
    )?;

    let mut rows = Vec::with_capacity(parameter_set.core.k);
    for row in matrix.rows_iter() {
        rows.push(ntt_dot(row, vector_hat).inverse_ntt());
    }

    PolyVector::from_polys(parameter_set.core.k, rows)
}

pub(crate) fn scalar_multiply_ntt_vector(
    scalar_hat: &NttPoly,
    vector_hat: &[NttPoly],
    expected_dimension: usize,
) -> DilithiumResult<PolyVector> {
    ensure_dimension("NTT vector dimension", expected_dimension, vector_hat.len())?;

    let products = vector_hat
        .iter()
        .map(|poly_hat| (scalar_hat * poly_hat).inverse_ntt())
        .collect();

    PolyVector::from_polys(expected_dimension, products)
}

pub(crate) fn power2_round_vector(
    vector: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<(PolyVector, PolyVector)> {
    let mut high = Vec::with_capacity(parameter_set.core.k);
    let mut low = Vec::with_capacity(parameter_set.core.k);

    for poly in vector.iter() {
        let mut high_coeffs = [Coefficient::default(); N];
        let mut low_coeffs = [Coefficient::default(); N];

        for index in 0..N {
            let rounded = poly
                .coeff(index)
                .expect("coefficient index is in range")
                .power2_round();
            high_coeffs[index] = Coefficient::from(rounded.high() as i32);
            low_coeffs[index] = Coefficient::centered(rounded.low() as i64);
        }

        high.push(Poly::from_coeffs(high_coeffs));
        low.push(Poly::from_coeffs(low_coeffs));
    }

    Ok((
        PolyVector::from_polys(parameter_set.core.k, high)?,
        PolyVector::from_polys(parameter_set.core.k, low)?,
    ))
}

pub(crate) fn high_bits_vector(
    vector: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    map_coefficients(vector, vector.dimension(), |coefficient| {
        Coefficient::from(coefficient.high_bits(parameter_set.core.gamma2) as i32)
    })
}

pub(crate) fn low_bits_vector(
    vector: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    map_coefficients(vector, vector.dimension(), |coefficient| {
        Coefficient::centered(coefficient.low_bits(parameter_set.core.gamma2) as i64)
    })
}

pub(crate) fn multiply_by_2_power_d(vector: &PolyVector) -> DilithiumResult<PolyVector> {
    map_coefficients(vector, vector.dimension(), |coefficient| {
        Coefficient::canonical((coefficient.value() as i64) << D)
    })
}

pub(crate) fn infinity_norm_at_least(vector: &PolyVector, bound: u32) -> bool {
    vector.iter().any(|poly| {
        poly.iter().any(|coefficient| {
            let centered = Coefficient::centered(coefficient.value() as i64).value();
            centered.unsigned_abs() >= bound
        })
    })
}

fn ntt_dot(row: &[NttPoly], vector_hat: &[NttPoly]) -> NttPoly {
    let mut sum = NttPoly::zero();
    for (lhs, rhs) in row.iter().zip(vector_hat.iter()) {
        let product = lhs * rhs;
        sum = &sum + &product;
    }
    sum
}

fn map_coefficients<F: FnMut(Coefficient) -> Coefficient>(
    vector: &PolyVector,
    dimension: usize,
    mut map: F,
) -> DilithiumResult<PolyVector> {
    let polys = vector
        .iter()
        .map(|poly| Poly::from_coeffs(core::array::from_fn(|index| map(poly.coeffs()[index]))))
        .collect();
    PolyVector::from_polys(dimension, polys)
}

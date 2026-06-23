//! Domain type and componentwise operations for ML-DSA hint vectors.
//!
//! A hint vector is not just any [`crate::poly::PolyVector`]: for one FIPS 204
//! parameter set it must have dimension `k`, binary coefficients, and Hamming
//! weight at most `omega`.

use crate::coefficient::Coefficient;
use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{N, ParameterSet};
use crate::poly::{Poly, PolyVector};
use crate::validation::ensure_dimension;

/// Sparse binary hint vector used by ML-DSA signing and verification.
///
/// The constructor enforces the FIPS 204 structural invariants for the supplied
/// parameter set: dimension `k`, coefficients in `{0, 1}`, and total weight at
/// most `omega`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HintsVector {
    parameter_set: ParameterSet,
    vector: PolyVector,
    weight: usize,
}

impl HintsVector {
    /// Builds a hint vector after validating all FIPS 204 hint invariants.
    pub fn new(parameter_set: ParameterSet, vector: PolyVector) -> DilithiumResult<Self> {
        ensure_dimension(
            "hint vector dimension",
            parameter_set.core.k,
            vector.dimension(),
        )?;

        let weight = vector.binary_weight()?;
        let omega = parameter_set.core.omega as usize;
        if weight > omega {
            return Err(DilithiumError::ValueOutOfRange {
                item: "hint weight",
                min: 0,
                max: omega as i64,
                actual: weight as i64,
            });
        }

        Ok(Self {
            parameter_set,
            vector,
            weight,
        })
    }

    /// Applies FIPS 204 `MakeHint` componentwise to two polynomial vectors.
    ///
    /// Both vectors must have dimension `parameter_set.core.k`. The returned
    /// value is validated as a [`HintsVector`], including the `omega` bound.
    pub fn make(
        parameter_set: ParameterSet,
        z: &PolyVector,
        r: &PolyVector,
    ) -> DilithiumResult<Self> {
        ensure_dimension(
            "hint source vector dimension",
            parameter_set.core.k,
            z.dimension(),
        )?;
        ensure_dimension(
            "hint target vector dimension",
            parameter_set.core.k,
            r.dimension(),
        )?;

        let polys = z
            .iter()
            .zip(r.iter())
            .map(|(z_poly, r_poly)| {
                Poly::from_coeffs(core::array::from_fn(|index| {
                    let hint = r_poly
                        .coeff(index)
                        .expect("coefficient index is in range")
                        .make_hint(
                            z_poly.coeff(index).expect("coefficient index is in range"),
                            parameter_set.core.gamma2,
                        );
                    Coefficient::from(if hint { 1 } else { 0 })
                }))
            })
            .collect();

        Self::new(
            parameter_set,
            PolyVector::from_polys(parameter_set.core.k, polys)?,
        )
    }

    /// Applies FIPS 204 `UseHint` componentwise to this hint vector and `r`.
    ///
    /// The `r` vector must have dimension `parameter_set.core.k`. The returned
    /// vector contains adjusted high-bit values as canonical coefficients.
    pub fn use_on(&self, r: &PolyVector) -> DilithiumResult<PolyVector> {
        ensure_dimension(
            "hint target vector dimension",
            self.parameter_set.core.k,
            r.dimension(),
        )?;

        let mut polys = Vec::with_capacity(self.vector.dimension());

        for (hint_poly, r_poly) in self.vector.iter().zip(r.iter()) {
            let mut coeffs = [Coefficient::default(); N];

            for (index, coefficient) in coeffs.iter_mut().enumerate() {
                let hint = hint_poly
                    .coeff(index)
                    .expect("coefficient index is in range")
                    .value();
                let adjusted = r_poly
                    .coeff(index)
                    .expect("coefficient index is in range")
                    .use_hint(hint == 1, self.parameter_set.core.gamma2);
                *coefficient = Coefficient::from(adjusted as i32);
            }

            polys.push(Poly::from_coeffs(coeffs));
        }

        PolyVector::from_polys(self.vector.dimension(), polys)
    }

    /// Returns the parameter set whose `k`, `gamma2`, and `omega` define this hint vector.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Returns the underlying validated polynomial vector.
    pub fn as_vector(&self) -> &PolyVector {
        &self.vector
    }

    /// Consumes this value and returns the underlying validated polynomial vector.
    pub fn into_vector(self) -> PolyVector {
        self.vector
    }

    /// Returns the number of polynomials in the hint vector.
    pub fn dimension(&self) -> usize {
        self.vector.dimension()
    }

    /// Returns the total number of one coefficients in the hint vector.
    pub fn weight(&self) -> usize {
        self.weight
    }

    /// Returns an iterator over the hint polynomials.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Poly> + '_ {
        self.vector.iter()
    }
}

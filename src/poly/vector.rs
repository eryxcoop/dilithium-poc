//! Polynomial-vector type for ML-DSA.

use crate::coefficient::Coefficient;
use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{D, N, ParameterSet};
use crate::poly::NttPolyVector;
use crate::poly::Poly;
use crate::validation::{ensure_dimension, ensure_len};

/// Vector of polynomials with a fixed runtime dimension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyVector {
    dimension: usize,
    polys: Vec<Poly>,
}

impl PolyVector {
    /// Returns a zero vector with the requested dimension.
    pub fn zero(dimension: usize) -> Self {
        Self {
            dimension,
            polys: vec![Poly::zero(); dimension],
        }
    }

    /// Returns a zero vector with the `l` dimension of the parameter set.
    pub fn zero_l(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.l)
    }

    /// Returns a zero vector with the `k` dimension of the parameter set.
    pub fn zero_k(parameter_set: ParameterSet) -> Self {
        Self::zero(parameter_set.core.k)
    }

    /// Builds a vector from explicit polynomials.
    pub fn from_polys(dimension: usize, polys: Vec<Poly>) -> DilithiumResult<Self> {
        ensure_len("polynomial vector", dimension, polys.len())?;
        Ok(Self { dimension, polys })
    }

    /// Returns the vector dimension.
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns `true` when the vector contains no polynomials.
    pub fn is_empty(&self) -> bool {
        self.dimension == 0
    }

    /// Returns one polynomial by index.
    pub fn get(&self, index: usize) -> Option<&Poly> {
        self.polys.get(index)
    }

    /// Returns an iterator over the polynomials.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Poly> + '_ {
        self.polys.iter()
    }

    /// Returns the polynomial slice.
    pub fn polys(&self) -> &[Poly] {
        &self.polys
    }

    /// Applies the forward NTT to every polynomial in the vector.
    ///
    /// ML-DSA expands the public matrix `A` directly as `Â` in the NTT domain.
    /// This prepares coefficient-domain vectors such as `s₁`, `s₂`, `t₀`, and
    /// `z` for multiplication with NTT-domain matrix or challenge values.
    pub(crate) fn ntt(&self) -> DilithiumResult<NttPolyVector> {
        NttPolyVector::from_polys(self.dimension, self.polys.iter().map(Poly::ntt).collect())
    }

    /// Returns the number of one coefficients in a binary polynomial vector.
    ///
    /// This helper is useful for ML-DSA hint vectors, where every coefficient
    /// must be either `0` or `1` and the total number of ones is bounded by
    /// `omega`. It returns [`DilithiumError::ValueOutOfRange`] if any coefficient
    /// is not binary.
    pub fn binary_weight(&self) -> DilithiumResult<usize> {
        let mut weight = 0usize;

        for poly in self.iter() {
            for coefficient in poly.iter() {
                match coefficient.value() {
                    0 => {}
                    1 => weight += 1,
                    value => {
                        return Err(DilithiumError::ValueOutOfRange {
                            item: "hint coefficient",
                            min: 0,
                            max: 1,
                            actual: value as i64,
                        });
                    }
                }
            }
        }

        Ok(weight)
    }

    /// Adds two vectors coefficientwise after checking that dimensions match.
    pub fn checked_add(&self, rhs: &Self) -> DilithiumResult<Self> {
        self.ensure_same_dimension(rhs)?;
        Ok(Self {
            dimension: self.dimension,
            polys: self
                .polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(lhs, rhs)| lhs + rhs)
                .collect(),
        })
    }

    /// Subtracts two vectors coefficientwise after checking that dimensions match.
    pub fn checked_sub(&self, rhs: &Self) -> DilithiumResult<Self> {
        self.ensure_same_dimension(rhs)?;
        Ok(Self {
            dimension: self.dimension,
            polys: self
                .polys
                .iter()
                .zip(rhs.polys.iter())
                .map(|(lhs, rhs)| lhs - rhs)
                .collect(),
        })
    }

    /// Returns the coefficientwise modular negation of the vector.
    pub fn neg(&self) -> Self {
        Self {
            dimension: self.dimension,
            polys: self.polys.iter().map(|poly| -poly).collect(),
        }
    }

    /// Applies FIPS 204 `Power2Round` to every coefficient of the vector.
    ///
    /// Key generation uses this to split `t = Âs₁ + s₂` into `(t₁, t₀)`, where
    /// `t₁` is encoded in the public key and `t₀` remains in the expanded
    /// private key. The returned vectors both have dimension `k`.
    pub(crate) fn power2_round(
        &self,
        parameter_set: ParameterSet,
    ) -> DilithiumResult<(Self, Self)> {
        let mut high = Vec::with_capacity(parameter_set.core.k);
        let mut low = Vec::with_capacity(parameter_set.core.k);

        for poly in self.iter() {
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
            Self::from_polys(parameter_set.core.k, high)?,
            Self::from_polys(parameter_set.core.k, low)?,
        ))
    }

    /// Applies FIPS 204 `HighBits` to every coefficient of the vector.
    ///
    /// Signing uses this to derive `w₁ = HighBits(w)` before hashing
    /// `μ || w1Encode(w₁)` into the challenge seed `c̃`.
    pub(crate) fn high_bits(&self, parameter_set: ParameterSet) -> DilithiumResult<Self> {
        self.map_coefficients(self.dimension, |coefficient| {
            Coefficient::from(coefficient.high_bits(parameter_set.core.gamma2) as i32)
        })
    }

    /// Applies FIPS 204 `LowBits` to every coefficient of the vector.
    ///
    /// Signing uses this for `r₀ = LowBits(w - c·s₂)`, which is one of the
    /// rejection-loop bounds checked before a signature attempt is accepted.
    pub(crate) fn low_bits(&self, parameter_set: ParameterSet) -> DilithiumResult<Self> {
        self.map_coefficients(self.dimension, |coefficient| {
            Coefficient::centered(coefficient.low_bits(parameter_set.core.gamma2) as i64)
        })
    }

    /// Multiplies every coefficient by `2ᵈ` using the global ML-DSA `d`.
    ///
    /// Verification reconstructs the high-order contribution of the public key
    /// as `t₁·2ᵈ` before computing `Âz - c·t₁·2ᵈ`.
    pub(crate) fn multiply_by_2_power_d(&self) -> DilithiumResult<Self> {
        self.map_coefficients(self.dimension, |coefficient| {
            Coefficient::canonical((coefficient.value() as i64) << D)
        })
    }

    /// Returns whether the centered infinity norm is at least `bound`.
    ///
    /// FIPS 204 rejection checks use `≥` comparisons for bounds such as
    /// `γ₁ - β`, `γ₂ - β`, and `γ₂`. Coefficients are interpreted in centered
    /// representation before taking absolute values.
    pub(crate) fn infinity_norm_at_least(&self, bound: u32) -> bool {
        self.iter().any(|poly| {
            poly.iter().any(|coefficient| {
                let centered = Coefficient::centered(coefficient.value() as i64).value();
                centered.unsigned_abs() >= bound
            })
        })
    }

    fn ensure_same_dimension(&self, rhs: &Self) -> DilithiumResult<()> {
        ensure_dimension("polynomial vector dimension", self.dimension, rhs.dimension)
    }

    fn map_coefficients<F: FnMut(Coefficient) -> Coefficient>(
        &self,
        dimension: usize,
        mut map: F,
    ) -> DilithiumResult<Self> {
        let polys = self
            .iter()
            .map(|poly| Poly::from_coeffs(core::array::from_fn(|index| map(poly.coeffs()[index]))))
            .collect();
        Self::from_polys(dimension, polys)
    }
}

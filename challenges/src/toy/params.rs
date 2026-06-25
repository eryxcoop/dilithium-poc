//! Runtime toy parameter metadata.

/// Errors returned by toy algebra operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToyAlgebraError {
    /// The toy ring degree must be non-zero.
    ZeroDegree,
    /// The toy modulus must be at least 2.
    InvalidModulus,
    /// Two toy objects belong to different rings.
    ParameterMismatch,
    /// A coefficient vector has the wrong length for the ring degree.
    LengthMismatch { expected: usize, actual: usize },
    /// A vector operation received the wrong number of polynomials.
    DimensionMismatch { expected: usize, actual: usize },
}

/// Parameters for the toy ring `Z_q[X] / (X^n + 1)`.
///
/// This is for classroom experiments only. It is not FIPS 204 metadata, and it
/// must not be converted into a production [`dilithium_poc::params::ParameterSet`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToyParams {
    degree: usize,
    modulus: i64,
}

impl ToyParams {
    /// Creates toy ring parameters.
    pub fn new(degree: usize, modulus: i64) -> Result<Self, ToyAlgebraError> {
        if degree == 0 {
            return Err(ToyAlgebraError::ZeroDegree);
        }
        if modulus < 2 {
            return Err(ToyAlgebraError::InvalidModulus);
        }
        Ok(Self { degree, modulus })
    }

    /// Returns `n`, the ring degree.
    pub fn degree(self) -> usize {
        self.degree
    }

    /// Returns `q`, the coefficient modulus.
    pub fn modulus(self) -> i64 {
        self.modulus
    }

    /// Reduces a coefficient into the canonical interval `[0, q)`.
    pub fn reduce(self, value: i64) -> i64 {
        value.rem_euclid(self.modulus)
    }

    /// Converts a coefficient to a centered representative.
    pub fn centered(self, value: i64) -> i64 {
        let reduced = self.reduce(value);
        if reduced > self.modulus / 2 {
            reduced - self.modulus
        } else {
            reduced
        }
    }
}

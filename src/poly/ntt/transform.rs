//! Forward and inverse NTT implementations.

use crate::params::N;
use crate::poly::Poly;
use crate::poly::ntt::domain::NttPoly;
use crate::poly::ntt::tables::{inverse_of_n, zetas_table};

impl Poly {
    /// Computes the FIPS 204 NTT of this polynomial.
    ///
    /// This maps a [`Poly`] from the coefficient domain `R_q` into the
    /// transform domain `T_q`, where multiplication becomes pointwise.
    pub fn ntt(&self) -> NttPoly {
        forward_impl(self)
    }
}

pub(super) fn forward_impl(poly: &Poly) -> NttPoly {
    let zetas = zetas_table();
    let mut values = *poly.coeffs();
    let mut m = 0usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let zeta = zetas[m];
            for j in start..(start + len) {
                let t = zeta * values[j + len];
                values[j + len] = values[j] - t;
                values[j] = values[j] + t;
            }
            start += 2 * len;
        }
        if len == 1 {
            break;
        }
        len /= 2;
    }

    NttPoly::from_coeffs(values)
}

pub(super) fn inverse_impl(value: &NttPoly) -> Poly {
    let zetas = zetas_table();
    let mut values = *value.coeffs();
    let mut m = 256usize;
    let mut len = 1usize;

    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let zeta = -zetas[m];
            for j in start..(start + len) {
                let t = values[j];
                values[j] = t + values[j + len];
                values[j + len] = (t - values[j + len]) * zeta;
            }
            start += 2 * len;
        }
        len *= 2;
    }

    let inverse_of_n = inverse_of_n();
    for coeff in &mut values {
        *coeff = inverse_of_n * *coeff;
    }

    Poly::from_coeffs(values)
}

//! Hint-vector packing and unpacking helpers from FIPS 204 Section 7.2.
//!
//! Hints are sparse binary polynomial vectors with dimension `k`. FIPS 204
//! encodes them as `ω + k` bytes: the first `ω` bytes hold coefficient
//! positions and the last `k` bytes hold cumulative per-polynomial boundaries.
//!
//! Conceptually, for `omega = 8` and `k = 4`, a hint vector with ones at
//! `h[0] = [0, 7]`, `h[1] = [3]`, `h[2] = []`, and `h[3] = [255]` is encoded as:
//!
//! ```text
//! encoding[0..omega]        = [0, 7, 3, 255, 0, 0, 0, 0]
//! encoding[omega..omega+k]  = [2, 3, 3, 4]
//! ```
//!
//! The boundary bytes `[2, 3, 3, 4]` mean:
//!
//! ```text
//! h[0] uses encoding[0..2]
//! h[1] uses encoding[2..3]
//! h[2] uses encoding[3..3]
//! h[3] uses encoding[3..4]
//! ```

use crate::coefficient::Coefficient;
use crate::error::{DilithiumError, DilithiumResult};
use crate::hints::HintsVector;
use crate::params::{N, ParameterSet};
use crate::poly::{Poly, PolyVector};

/// Encodes one binary hint vector using FIPS 204 `HintBitPack`.
///
/// The vector dimension must match `parameter_set.core.k`; coefficients must be
/// binary (`0` or `1`); and the total number of one coefficients must be at most
/// `parameter_set.core.omega`.
pub fn hint_bit_pack(hints: &HintsVector) -> DilithiumResult<Vec<u8>> {
    let parameter_set = hints.parameter_set();

    let omega = parameter_set.core.omega as usize;
    let k = parameter_set.core.k;
    let mut encoding = vec![0u8; omega + k];
    let mut hint_count = 0usize;

    for (poly_index, poly) in hints.iter().enumerate() {
        for (coeff_index, coefficient) in poly.iter().enumerate() {
            let value = coefficient.value();
            if value != 0 {
                encoding[hint_count] = coeff_index as u8;
                hint_count += 1;
            }
        }

        encoding[omega + poly_index] = hint_count as u8;
    }

    Ok(encoding)
}

/// Decodes one binary hint vector using FIPS 204 `HintBitUnpack`.
///
/// This function implements the strict malformed-input checks from FIPS 204
/// Algorithm 21: cumulative boundaries must be monotonic and at most `ω`;
/// positions inside each polynomial must be strictly increasing; and unused
/// bytes in the first `ω` bytes must be zero.
pub fn hint_bit_unpack(
    encoding: &[u8],
    parameter_set: ParameterSet,
) -> DilithiumResult<HintsVector> {
    let omega = parameter_set.core.omega as usize;
    let k = parameter_set.core.k;
    ensure_hint_encoding_len(encoding, omega + k)?;

    let mut polys = vec![Poly::zero(); k];
    let mut hint_count = 0usize;

    for (poly_index, poly) in polys.iter_mut().enumerate() {
        let boundary = encoding[omega + poly_index] as usize;
        if boundary < hint_count || boundary > omega {
            return Err(DilithiumError::MalformedEncoding(
                "hint boundary is not monotonic or exceeds omega",
            ));
        }

        let poly_start_hint_count = hint_count;
        let mut coeffs = [Coefficient::default(); N];

        while hint_count < boundary {
            if hint_count > poly_start_hint_count
                && encoding[hint_count - 1] >= encoding[hint_count]
            {
                return Err(DilithiumError::MalformedEncoding(
                    "hint indices are not strictly increasing",
                ));
            }

            coeffs[encoding[hint_count] as usize] = Coefficient::from(1);
            hint_count += 1;
        }

        *poly = Poly::from_coeffs(coeffs);
    }

    for &byte in &encoding[hint_count..omega] {
        if byte != 0 {
            return Err(DilithiumError::MalformedEncoding(
                "unused hint index byte is nonzero",
            ));
        }
    }

    HintsVector::new(parameter_set, PolyVector::from_polys(k, polys)?)
}

fn ensure_hint_encoding_len(encoding: &[u8], expected: usize) -> DilithiumResult<()> {
    if encoding.len() == expected {
        Ok(())
    } else {
        Err(DilithiumError::InvalidLength {
            expected,
            actual: encoding.len(),
            item: "hint encoding",
        })
    }
}

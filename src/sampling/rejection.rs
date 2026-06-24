//! Rejection samplers for bounded and NTT-domain polynomials.
//!
//! FIPS 204 builds several ML-DSA objects by reading deterministic bytes from
//! SHAKE and accepting only byte patterns that map into the required coefficient
//! domain. A rejected candidate is not an error; it is the normal rejection
//! sampling path and simply causes the sampler to squeeze more XOF output.
//!
//! This module implements:
//!
//! - `RejNTTPoly`, used by `ExpandA` to sample entries of the public matrix
//!   `Â` directly in the NTT domain `T_q`.
//! - `RejBoundedPoly`, used by `ExpandS` to sample secret polynomials with
//!   coefficients in `[-η, η]`.
//!
//! The `_with_limits` variants return [`Sampled`] so callers can inspect
//! instrumentation such as loop iterations, XOF bytes consumed, and rejected
//! candidates. The plain variants return only the sampled polynomial.

use crate::coefficient::Coefficient;
use crate::error::DilithiumResult;
use crate::params::N;
use crate::poly::{NttPoly, Poly};
use crate::sampling::coefficients::{
    coeff_from_half_byte, coeff_from_three_bytes, ensure_supported_eta,
};
use crate::sampling::constants::{RejBoundedPolySeed, RejNttPolySeed};
use crate::sampling::limits::{SamplingLimits, increment_loop_limit};
use crate::sampling::report::{Sampled, SamplingReport};
use crate::sampling::xof_reader::CountingXof;
use crate::xof::{shake128_reader, shake256_reader};

/// FIPS 204 Algorithm 30, `RejNTTPoly(ρ)`.
///
/// This convenience wrapper runs without optional Table 3 caps and returns only
/// the sampled transform-domain polynomial.
pub fn rej_ntt_poly(seed: RejNttPolySeed) -> DilithiumResult<NttPoly> {
    Ok(rej_ntt_poly_with_limits(seed, SamplingLimits::default())?.into_value())
}

/// `RejNTTPoly` with optional Table 3 limits and instrumentation.
///
/// `RejNTTPoly` uses `G = SHAKE128`. Each loop iteration consumes three bytes,
/// interprets them with `CoeffFromThreeBytes`, and accepts the candidate only
/// when it is less than `q`. The loop stops after exactly 256 accepted
/// coefficients, producing an [`NttPoly`].
pub fn rej_ntt_poly_with_limits(
    seed: RejNttPolySeed,
    limits: SamplingLimits,
) -> DilithiumResult<Sampled<NttPoly>> {
    limits.validate()?;

    let mut coeffs = [Coefficient::default(); N];
    let mut report = SamplingReport::default();
    let rej_ntt_limits = limits.rej_ntt_poly();
    let mut reader = CountingXof::new(
        "RejNTTPoly",
        shake128_reader(seed.as_bytes()),
        rej_ntt_limits.xof_bytes(),
    );
    let mut index = 0usize;

    while index < N {
        increment_loop_limit("RejNTTPoly", rej_ntt_limits.loop_iterations(), &mut report)?;

        let sample = reader.squeeze_array::<3>()?;
        if let Some(coefficient) = coeff_from_three_bytes(sample[0], sample[1], sample[2]) {
            coeffs[index] = coefficient;
            index += 1;
        } else {
            report.record_rejection();
        }
    }

    report.set_xof_bytes(reader.bytes_read());
    Ok(Sampled::new(NttPoly::from_coeffs(coeffs), report))
}

/// FIPS 204 Algorithm 31, `RejBoundedPoly(ρ)`.
///
/// This convenience wrapper runs without optional Table 3 caps and returns only
/// the sampled coefficient-domain polynomial.
pub fn rej_bounded_poly(seed: RejBoundedPolySeed, eta: u32) -> DilithiumResult<Poly> {
    Ok(rej_bounded_poly_with_limits(seed, eta, SamplingLimits::default())?.into_value())
}

/// `RejBoundedPoly` with optional Table 3 limits and instrumentation.
///
/// `RejBoundedPoly` uses `H = SHAKE256`. Each loop iteration consumes one byte
/// and tries to turn both nibbles into coefficients via `CoeffFromHalfByte`.
/// Depending on `η`, each nibble may be accepted as a coefficient in
/// `[-η, η]` or rejected. The loop stops after exactly 256 accepted
/// coefficients, producing a [`Poly`].
///
/// The loop counter and rejection counter intentionally measure different
/// things here: one loop iteration is one squeezed byte, while one rejection is
/// one rejected nibble. A single byte can therefore contribute zero, one, or two
/// accepted coefficients and can also contribute zero, one, or two rejections.
pub fn rej_bounded_poly_with_limits(
    seed: RejBoundedPolySeed,
    eta: u32,
    limits: SamplingLimits,
) -> DilithiumResult<Sampled<Poly>> {
    limits.validate()?;
    ensure_supported_eta(eta)?;

    let mut coeffs = [Coefficient::default(); N];
    let mut report = SamplingReport::default();
    let rej_bounded_limits = limits.rej_bounded_poly();
    let mut reader = CountingXof::new(
        "RejBoundedPoly",
        shake256_reader(seed.as_bytes()),
        rej_bounded_limits.xof_bytes(),
    );
    let mut index = 0usize;

    while index < N {
        increment_loop_limit(
            "RejBoundedPoly",
            rej_bounded_limits.loop_iterations(),
            &mut report,
        )?;

        let byte = reader.squeeze_byte()?;
        let low = byte & 0x0f;
        let high = byte >> 4;

        if let Some(coefficient) = coeff_from_half_byte(low, eta) {
            coeffs[index] = coefficient;
            index += 1;
        } else {
            report.record_rejection();
        }

        if index < N {
            if let Some(coefficient) = coeff_from_half_byte(high, eta) {
                coeffs[index] = coefficient;
                index += 1;
            } else {
                report.record_rejection();
            }
        }
    }

    report.set_xof_bytes(reader.bytes_read());
    Ok(Sampled::new(Poly::from_coeffs(coeffs), report))
}

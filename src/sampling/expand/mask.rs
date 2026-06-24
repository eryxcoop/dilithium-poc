//! `ExpandMask` for ML-DSA signing masks.
//!
//! FIPS 204 uses `ExpandMask(ρ, μ)` inside `ML-DSA.Sign_internal` to derive
//! the ephemeral mask vector `y` for one signing-loop attempt. That mask is then
//! multiplied by the public matrix as `w = Â × y`, and the high bits of `w`
//! are hashed into the challenge. If the signing attempt is rejected, the caller
//! advances the mask counter and asks `ExpandMask` for a fresh deterministic
//! mask.
//!
//! Unlike `ExpandA(ρ)` and `ExpandS(ρ')`, this procedure does not use rejection
//! sampling. The `ExpandMask` coefficient range has power-of-two size:
//! `[-γ₁ + 1, γ₁]` contains `2γ₁` values, and ML-DSA chooses `γ₁ = 2¹⁷` or
//! `γ₁ = 2¹⁹`. That means every fixed-width bit pattern maps to a valid
//! coefficient, so there are no invalid candidates to reject. Each polynomial
//! coordinate reads an exact number of bytes from `H = SHAKE256` and decodes
//! those bytes with `BitUnpack(γ₁ - 1, γ₁)`.
//!
//! For each coordinate `r`, FIPS derives the SHAKE256 input as:
//!
//! ```text
//! ρ || IntegerToBytes(μ + r, 2)
//! ```
//!
//! The two-byte counter keeps every vector coordinate and every signing-loop
//! attempt in a distinct XOF domain while reusing the same 64-byte `ρ`.

use crate::encoding::{bit_length, bit_unpack};
use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::poly::PolyVector;
use crate::sampling::coefficients::{SamplingIndex, derive_indexed_bounded_seed};
use crate::sampling::constants::ExpandMaskSeed;
use crate::sampling::limits::SamplingLimits;
use crate::sampling::report::{Sampled, SamplingReport};
use crate::xof::shake256;

/// FIPS 204 Algorithm 34, `ExpandMask(ρ, μ)`.
///
/// This convenience wrapper runs without optional Table 3 caps and returns only
/// the sampled mask vector `y`. Use [`expand_mask_with_limits`] when callers
/// need the XOF-byte instrumentation.
pub fn expand_mask(
    seed: ExpandMaskSeed,
    mask_counter: u16,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    Ok(
        expand_mask_with_limits(seed, mask_counter, parameter_set, SamplingLimits::default())?
            .into_value(),
    )
}

/// `ExpandMask` with aggregated XOF-byte instrumentation.
///
/// `seed` is the 64-byte `ρ` input to FIPS `ExpandMask(ρ, μ)`, and
/// `mask_counter` is the two-byte base counter `μ`. For each row `r` in the
/// length-`l` output vector, this function derives:
///
/// ```text
/// ρ || IntegerToBytes(μ + row, 2)
/// ```
///
/// It then reads exactly `32 × (1 + bitlen(γ₁ - 1))` bytes from
/// `H = SHAKE256`. The factor `32` appears because each polynomial has `256`
/// coefficients and `256 / 8 = 32`; multiplying by the per-coefficient bit
/// width gives the byte length needed by `BitUnpack(γ₁ - 1, γ₁)`.
/// Since the target range has `2γ₁` values and `γ₁` is a power of two, that
/// bit width covers the range exactly and does not create rejected encodings.
///
/// The returned [`Sampled`] value contains the mask vector plus an aggregated
/// [`SamplingReport`]. Because `ExpandMask` does not reject candidates, the
/// report tracks only XOF bytes; loop iterations and rejection counters remain
/// zero.
pub fn expand_mask_with_limits(
    seed: ExpandMaskSeed,
    mask_counter: u16,
    parameter_set: ParameterSet,
    limits: SamplingLimits,
) -> DilithiumResult<Sampled<PolyVector>> {
    limits.validate()?;

    let bit_width = 1 + bit_length(parameter_set.core.gamma1 - 1);
    let out_len = 32 * bit_width;
    let mut polys = Vec::with_capacity(parameter_set.core.l);
    let mut report = SamplingReport::default();
    let base_index = SamplingIndex::new(mask_counter);

    for row in 0..parameter_set.core.l {
        let derived_seed =
            derive_indexed_bounded_seed(seed.bytes(), base_index.wrapping_add_usize(row));
        let bytes = shake256(derived_seed.as_bytes(), out_len);
        report.add_xof_bytes(bytes.len());
        polys.push(bit_unpack(
            &bytes,
            parameter_set.core.gamma1 - 1,
            parameter_set.core.gamma1,
        )?);
    }

    Ok(Sampled::new(
        PolyVector::from_polys(parameter_set.core.l, polys)?,
        report,
    ))
}

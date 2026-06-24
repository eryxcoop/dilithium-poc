//! Challenge-polynomial sampling.
//!
//! FIPS 204 uses `SampleInBall(ρ)` to turn the challenge seed `c̃` into the
//! sparse challenge polynomial `c`. The output is not an arbitrary polynomial:
//! it has exactly `τ` nonzero coefficients, each equal to `+1` or `-1`, and all
//! remaining coefficients are zero.
//!
//! During signing, `c̃ = H(μ || w1Encode(w1), λ / 4)` is sampled and then
//! expanded with `SampleInBall(c̃)`. During verification, the verifier repeats
//! the same expansion before recomputing the challenge hash, so this procedure
//! must be deterministic and byte-for-byte aligned with FIPS.
//!
//! The `λ / 4` length is a byte count passed to `H`. Since `λ` is measured in
//! bits, `λ / 4` bytes contain `8 × λ / 4 = 2λ` bits. Thus ML-DSA stores a
//! challenge seed `c̃` with `2λ` bits of entropy: 32 bytes for ML-DSA-44, 48
//! bytes for ML-DSA-65, and 64 bytes for ML-DSA-87.
//!
//! The first 64 XOF-derived bits choose the signs of the nonzero coefficients.
//! The positions are selected with rejection sampling plus a swap-based
//! selection step: each accepted byte selects an index in `0..=i`, and any
//! previous coefficient at that index is moved to `i`. This is the same idea
//! used by the Fisher-Yates shuffle, but only for the final `τ` placements.
//! It gives exactly `τ` distinct nonzero positions without storing a separate
//! “already used” set. See the
//! [Fisher-Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
//! for the general swap-based sampling technique.

use crate::coefficient::Coefficient;
use crate::encoding::bytes_to_bits;
use crate::error::{DilithiumError, DilithiumResult};
use crate::params::{N, ParameterSet};
use crate::poly::Poly;
use crate::sampling::limits::{SamplingLimits, increment_loop_limit};
use crate::sampling::report::{Sampled, SamplingReport};
use crate::sampling::xof_reader::CountingXof;
use crate::xof::shake256_reader;

/// FIPS 204 Algorithm 29, `SampleInBall(ρ)`.
///
/// This convenience wrapper runs without optional Table 3 caps and returns only
/// the sparse challenge polynomial `c`.
pub fn sample_in_ball(challenge_seed: &[u8], parameter_set: ParameterSet) -> DilithiumResult<Poly> {
    Ok(
        sample_in_ball_with_limits(challenge_seed, parameter_set, SamplingLimits::default())?
            .into_value(),
    )
}

/// `SampleInBall` with optional Table 3 limits and instrumentation.
///
/// `challenge_seed` is the `λ / 4`-byte seed `c̃` produced by hashing
/// `μ || w1Encode(w1)` during signing or verification. Its length is checked
/// against the active [`ParameterSet`] before any XOF bytes are consumed.
///
/// The algorithm starts from the all-zero polynomial and then performs `τ`
/// insertions. For each loop value `i` in `(N - τ)..N`, it draws a byte until
/// the byte is at most `i`; values greater than `i` are rejected because they
/// would be outside the current selectable prefix. The accepted index receives
/// the next sign bit, while any existing coefficient at that index is moved to
/// position `i`. This mirrors the swap step from the
/// [Fisher-Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle),
/// applied only to the sparse challenge positions.
///
/// The returned [`Sampled`] value contains the challenge polynomial plus a
/// [`SamplingReport`] with XOF bytes consumed and rejection-loop counters.
pub fn sample_in_ball_with_limits(
    challenge_seed: &[u8],
    parameter_set: ParameterSet,
    limits: SamplingLimits,
) -> DilithiumResult<Sampled<Poly>> {
    limits.validate()?;

    let expected = parameter_set.challenge_bytes();
    if challenge_seed.len() != expected {
        return Err(DilithiumError::InvalidLength {
            expected,
            actual: challenge_seed.len(),
            item: "SampleInBall seed",
        });
    }

    let mut coeffs = [Coefficient::default(); N];
    let mut report = SamplingReport::default();
    let sample_limits = limits.sample_in_ball();
    let mut reader = CountingXof::new(
        "SampleInBall",
        shake256_reader(challenge_seed),
        sample_limits.xof_bytes(),
    );

    let signs = bytes_to_bits(&reader.squeeze_vec(8)?);
    let tau = parameter_set.core.tau as usize;

    for i in (N - tau)..N {
        let mut selected = reader.squeeze_byte()?;
        while selected as usize > i {
            increment_loop_limit("SampleInBall", sample_limits.loop_iterations(), &mut report)?;
            report.record_rejection();
            selected = reader.squeeze_byte()?;
        }

        coeffs[i] = coeffs[selected as usize];
        let sign = if signs[i + tau - N] == 0 { 1 } else { -1 };
        coeffs[selected as usize] = Coefficient::centered(sign);
    }

    report.set_xof_bytes(reader.bytes_read());
    Ok(Sampled::new(Poly::from_coeffs(coeffs), report))
}

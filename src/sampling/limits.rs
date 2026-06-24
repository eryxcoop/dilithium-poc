//! Optional FIPS 204 Table 3 sampling limits.
//!
//! FIPS 204 permits implementations to cap selected rejection-sampling loops
//! or XOF output consumption, but those caps must not be lower than the
//! standard's Table 3 minima. A too-small cap would make a correct execution
//! fail with non-negligible probability.
//!
//! In this module, `None` means "no implementation cap." When a cap is present,
//! [`SamplingLimits::validate`] rejects values below Table 3 with
//! [`DilithiumError::LimitTooSmall`]. During sampling,
//! [`increment_loop_limit`] returns [`DilithiumError::SamplingLimitExceeded`]
//! if an enabled cap is reached.

use crate::error::{DilithiumError, DilithiumResult};
use crate::sampling::constants::{
    REJ_BOUNDED_POLY_MIN_LOOP_LIMIT, REJ_BOUNDED_POLY_MIN_XOF_BYTES, REJ_NTT_POLY_MIN_LOOP_LIMIT,
    REJ_NTT_POLY_MIN_XOF_BYTES, SAMPLE_IN_BALL_MIN_LOOP_LIMIT, SAMPLE_IN_BALL_MIN_XOF_BYTES,
};
use crate::sampling::report::SamplingReport;

/// Optional execution limits for one sampling algorithm.
///
/// Each field is optional because FIPS 204 does not require implementations to
/// impose caps. The caps exist as a hard-stop defense for faulty executions or
/// bounded environments; normal conforming executions should not reach Table 3
/// minima except with probability about `2^-256` or less.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlgorithmSamplingLimits {
    /// Maximum allowable algorithm-specific loop iterations.
    ///
    /// For `SampleInBall`, this counts the rejection-loop body executions from
    /// step 8 of FIPS 204 Algorithm 29.
    loop_iterations: Option<usize>,
    /// Maximum allowable bytes extracted from the underlying XOF.
    xof_bytes: Option<usize>,
}

impl AlgorithmSamplingLimits {
    /// Returns an unlimited configuration for one sampling algorithm.
    pub const fn unlimited() -> Self {
        Self::new(None, None)
    }

    /// Builds limits from optional loop-iteration and XOF-byte caps.
    ///
    /// Passing `None` for a component disables that specific cap.
    pub const fn new(loop_iterations: Option<usize>, xof_bytes: Option<usize>) -> Self {
        Self {
            loop_iterations,
            xof_bytes,
        }
    }

    /// Builds limits with only a loop-iteration cap enabled.
    pub const fn with_loop_iterations(loop_iterations: usize) -> Self {
        Self::new(Some(loop_iterations), None)
    }

    /// Builds limits with only an XOF-byte cap enabled.
    pub const fn with_xof_bytes(xof_bytes: usize) -> Self {
        Self::new(None, Some(xof_bytes))
    }

    /// Builds limits with both a loop-iteration and an XOF-byte cap enabled.
    pub const fn with_both(loop_iterations: usize, xof_bytes: usize) -> Self {
        Self::new(Some(loop_iterations), Some(xof_bytes))
    }

    /// Returns the optional loop-iteration cap.
    pub const fn loop_iterations(self) -> Option<usize> {
        self.loop_iterations
    }

    /// Returns the optional XOF-byte cap.
    pub const fn xof_bytes(self) -> Option<usize> {
        self.xof_bytes
    }
}

/// Optional Table 3 limits for the M3 sampling procedures.
///
/// This groups the algorithms from milestone M3 that have Table 3 limits:
/// `RejBoundedPoly`, `RejNTTPoly`, and `SampleInBall`. `ML-DSA.Sign_internal`
/// also has a Table 3 loop minimum, but the signing loop is implemented in a
/// later milestone, so only its constant lives in [`crate::sampling::constants`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SamplingLimits {
    /// Limits for `RejBoundedPoly`.
    rej_bounded_poly: AlgorithmSamplingLimits,
    /// Limits for `RejNTTPoly`.
    rej_ntt_poly: AlgorithmSamplingLimits,
    /// Limits for `SampleInBall`.
    sample_in_ball: AlgorithmSamplingLimits,
}

impl SamplingLimits {
    /// Builds a complete limit set for all M3 sampling procedures.
    pub const fn new(
        rej_bounded_poly: AlgorithmSamplingLimits,
        rej_ntt_poly: AlgorithmSamplingLimits,
        sample_in_ball: AlgorithmSamplingLimits,
    ) -> Self {
        Self {
            rej_bounded_poly,
            rej_ntt_poly,
            sample_in_ball,
        }
    }

    /// Returns a limit set that enables the exact Table 3 minima.
    ///
    /// These are the smallest limits allowed by FIPS 204:
    ///
    /// - `RejBoundedPoly`: 481 loop iterations and 481 XOF bytes.
    /// - `RejNTTPoly`: 298 loop iterations and 894 XOF bytes.
    /// - `SampleInBall`: 121 rejection-loop iterations and 221 XOF bytes.
    pub const fn fips_table_3() -> Self {
        Self {
            rej_bounded_poly: AlgorithmSamplingLimits::with_both(
                REJ_BOUNDED_POLY_MIN_LOOP_LIMIT,
                REJ_BOUNDED_POLY_MIN_XOF_BYTES,
            ),
            rej_ntt_poly: AlgorithmSamplingLimits::with_both(
                REJ_NTT_POLY_MIN_LOOP_LIMIT,
                REJ_NTT_POLY_MIN_XOF_BYTES,
            ),
            sample_in_ball: AlgorithmSamplingLimits::with_both(
                SAMPLE_IN_BALL_MIN_LOOP_LIMIT,
                SAMPLE_IN_BALL_MIN_XOF_BYTES,
            ),
        }
    }

    /// Returns the `RejBoundedPoly` limits.
    pub const fn rej_bounded_poly(self) -> AlgorithmSamplingLimits {
        self.rej_bounded_poly
    }

    /// Returns the `RejNTTPoly` limits.
    pub const fn rej_ntt_poly(self) -> AlgorithmSamplingLimits {
        self.rej_ntt_poly
    }

    /// Returns the `SampleInBall` limits.
    pub const fn sample_in_ball(self) -> AlgorithmSamplingLimits {
        self.sample_in_ball
    }

    /// Returns a copy with replacement `RejBoundedPoly` limits.
    pub const fn with_rej_bounded_poly(mut self, limits: AlgorithmSamplingLimits) -> Self {
        self.rej_bounded_poly = limits;
        self
    }

    /// Returns a copy with replacement `RejNTTPoly` limits.
    pub const fn with_rej_ntt_poly(mut self, limits: AlgorithmSamplingLimits) -> Self {
        self.rej_ntt_poly = limits;
        self
    }

    /// Returns a copy with replacement `SampleInBall` limits.
    pub const fn with_sample_in_ball(mut self, limits: AlgorithmSamplingLimits) -> Self {
        self.sample_in_ball = limits;
        self
    }

    /// Validates that all enabled caps satisfy the Table 3 lower bounds.
    ///
    /// This intentionally validates limits before sampling starts, so a caller
    /// receives [`DilithiumError::LimitTooSmall`] for invalid configuration
    /// instead of a data-dependent failure partway through an algorithm.
    pub(super) fn validate(&self) -> DilithiumResult<()> {
        validate_algorithm_limits(
            "RejBoundedPoly",
            self.rej_bounded_poly,
            REJ_BOUNDED_POLY_MIN_LOOP_LIMIT,
            REJ_BOUNDED_POLY_MIN_XOF_BYTES,
        )?;
        validate_algorithm_limits(
            "RejNTTPoly",
            self.rej_ntt_poly,
            REJ_NTT_POLY_MIN_LOOP_LIMIT,
            REJ_NTT_POLY_MIN_XOF_BYTES,
        )?;
        validate_algorithm_limits(
            "SampleInBall",
            self.sample_in_ball,
            SAMPLE_IN_BALL_MIN_LOOP_LIMIT,
            SAMPLE_IN_BALL_MIN_XOF_BYTES,
        )?;
        Ok(())
    }
}

/// Checks one loop iteration against an optional cap and records it.
///
/// The check happens before incrementing the report. If the report already
/// contains `limit` iterations, the next attempted iteration fails with
/// [`DilithiumError::SamplingLimitExceeded`]. This keeps the limit semantics
/// consistent across samplers.
pub(super) fn increment_loop_limit(
    algorithm: &'static str,
    limit: Option<usize>,
    report: &mut SamplingReport,
) -> DilithiumResult<()> {
    if let Some(limit) = limit
        && report.loop_iterations() >= limit
    {
        return Err(DilithiumError::SamplingLimitExceeded {
            algorithm,
            limit_kind: "loop iterations",
            limit,
        });
    }
    report.record_loop_iteration();
    Ok(())
}

fn validate_algorithm_limits(
    algorithm: &'static str,
    limits: AlgorithmSamplingLimits,
    min_loop_iterations: usize,
    min_xof_bytes: usize,
) -> DilithiumResult<()> {
    if let Some(actual) = limits.loop_iterations
        && actual < min_loop_iterations
    {
        return Err(DilithiumError::LimitTooSmall {
            algorithm,
            limit_kind: "loop iterations",
            minimum: min_loop_iterations,
            actual,
        });
    }

    if let Some(actual) = limits.xof_bytes
        && actual < min_xof_bytes
    {
        return Err(DilithiumError::LimitTooSmall {
            algorithm,
            limit_kind: "xof bytes",
            minimum: min_xof_bytes,
            actual,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_loop_limit_fails_before_recording_beyond_cap() {
        let mut report = SamplingReport::default();

        increment_loop_limit("SampleInBall", Some(1), &mut report).unwrap();
        let error = increment_loop_limit("SampleInBall", Some(1), &mut report).unwrap_err();

        assert_eq!(report.loop_iterations(), 1);
        assert_eq!(
            error,
            DilithiumError::SamplingLimitExceeded {
                algorithm: "SampleInBall",
                limit_kind: "loop iterations",
                limit: 1,
            }
        );
    }
}

//! FIPS 204 SHAKE-based sampling procedures.
//!
//! This module implements the milestone-M3 primitives:
//! `RejNTTPoly`, `RejBoundedPoly`, `ExpandA`, `ExpandS`, `ExpandMask`, and
//! `SampleInBall`, plus optional Table 3 execution limits and lightweight
//! instrumentation.

mod challenge;
mod coefficients;
mod constants;
mod expand;
mod limits;
mod rejection;
mod report;
mod xof_reader;

pub use challenge::{sample_in_ball, sample_in_ball_with_limits};
pub use constants::{
    ExpandASeed, ExpandMaskSeed, ExpandSSeed, REJ_BOUNDED_POLY_MIN_LOOP_LIMIT,
    REJ_BOUNDED_POLY_MIN_XOF_BYTES, REJ_NTT_POLY_MIN_LOOP_LIMIT, REJ_NTT_POLY_MIN_XOF_BYTES,
    RejBoundedPolySeed, RejNttPolySeed, SAMPLE_IN_BALL_MIN_LOOP_LIMIT,
    SAMPLE_IN_BALL_MIN_XOF_BYTES, SIGN_INTERNAL_MIN_LOOP_LIMIT,
};
pub use expand::{
    expand_a, expand_a_with_limits, expand_mask, expand_mask_with_limits, expand_s,
    expand_s_with_limits,
};
pub use limits::{AlgorithmSamplingLimits, SamplingLimits};
pub use rejection::{
    rej_bounded_poly, rej_bounded_poly_with_limits, rej_ntt_poly, rej_ntt_poly_with_limits,
};
pub use report::{Sampled, SamplingReport};

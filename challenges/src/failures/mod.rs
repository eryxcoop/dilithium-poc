//! Intentionally vulnerable classroom demos.
//!
//! These runners are compiled only with the `failure-challenges` feature.

mod eta_unbounded_secret;
mod gamma1_beta_boundary_oracle;
mod gamma2_lowbits_boundary_oracle;
mod lambda_too_short_cross_message;
mod nonce_reuse;
mod sampler_patterned_y;
mod toy_dense_hint_forgery;
mod toy_params_too_small;
mod verifier_no_ctilde;

use crate::shared::ChallengeRun;

pub use eta_unbounded_secret::run as eta_unbounded_secret;
pub use gamma1_beta_boundary_oracle::run as gamma1_beta_boundary_oracle;
pub use gamma2_lowbits_boundary_oracle::run as gamma2_lowbits_boundary_oracle;
pub use lambda_too_short_cross_message::run as lambda_too_short_cross_message;
pub use nonce_reuse::run as nonce_reuse;
pub use sampler_patterned_y::run as sampler_patterned_y;
pub use toy_dense_hint_forgery::run as toy_dense_hint_forgery;
pub use toy_params_too_small::run as toy_params_too_small;
pub use verifier_no_ctilde::run as verifier_no_ctilde;

/// Runs every classroom challenge in catalog order.
pub fn challenge_runs() -> Vec<ChallengeRun> {
    vec![
        nonce_reuse(),
        sampler_patterned_y(),
        eta_unbounded_secret(),
        gamma1_beta_boundary_oracle(),
        gamma2_lowbits_boundary_oracle(),
        verifier_no_ctilde(),
        lambda_too_short_cross_message(),
        toy_dense_hint_forgery(),
        toy_params_too_small(),
    ]
}

/// Returns `true` when every classroom challenge succeeds.
pub fn challenges_success() -> bool {
    challenge_runs().iter().all(ChallengeRun::success)
}

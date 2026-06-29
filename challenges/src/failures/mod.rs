//! Intentionally vulnerable classroom demos.
//!
//! These runners are compiled only with the `failure-challenges` feature.

mod eta_unbounded_secret;
mod nonce_reuse;
mod sampler_patterned_y;
mod toy_dense_hint_forgery;
mod toy_params_too_small;
mod verifier_no_ctilde;

use crate::shared::ChallengeRun;

pub use eta_unbounded_secret::run as eta_unbounded_secret;
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
        verifier_no_ctilde(),
        toy_dense_hint_forgery(),
        toy_params_too_small(),
    ]
}

/// Returns `true` when every classroom challenge succeeds.
pub fn challenges_success() -> bool {
    challenge_runs().iter().all(ChallengeRun::success)
}

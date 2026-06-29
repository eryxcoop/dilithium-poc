//! Phase 1 intentionally vulnerable classroom demos.
//!
//! These runners use toy arithmetic or structural checks to make one broken
//! FIPS 204 rule visible at a time.

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

/// Runs every Phase 1 challenge in roadmap order.
pub fn phase1_runs() -> Vec<ChallengeRun> {
    vec![
        nonce_reuse(),
        sampler_patterned_y(),
        eta_unbounded_secret(),
        verifier_no_ctilde(),
        toy_dense_hint_forgery(),
        toy_params_too_small(),
    ]
}

/// Returns `true` when every Phase 1 exploit demonstration succeeds.
pub fn phase1_success() -> bool {
    phase1_runs().iter().all(ChallengeRun::success)
}

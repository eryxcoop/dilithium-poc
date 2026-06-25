//! Phase 1 intentionally vulnerable classroom demos.
//!
//! These runners use toy arithmetic or structural checks to make one broken
//! FIPS 204 rule visible at a time.

mod nonce_reuse;
mod sampler_patterned_y;
mod toy_params_too_small;
mod verifier_no_ctilde;
mod verifier_no_omega;
mod verifier_no_z_bound;

use crate::shared::ChallengeRun;

pub use nonce_reuse::run as nonce_reuse;
pub use sampler_patterned_y::run as sampler_patterned_y;
pub use toy_params_too_small::run as toy_params_too_small;
pub use verifier_no_ctilde::run as verifier_no_ctilde;
pub use verifier_no_omega::run as verifier_no_omega;
pub use verifier_no_z_bound::run as verifier_no_z_bound;

/// Runs every Phase 1 challenge in roadmap order.
pub fn phase1_runs() -> Vec<ChallengeRun> {
    vec![
        nonce_reuse(),
        sampler_patterned_y(),
        verifier_no_ctilde(),
        verifier_no_z_bound(),
        verifier_no_omega(),
        toy_params_too_small(),
    ]
}

/// Returns `true` when every Phase 1 exploit demonstration succeeds.
pub fn phase1_success() -> bool {
    phase1_runs().iter().all(ChallengeRun::success)
}

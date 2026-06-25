//! Student-facing Phase 1 exercise stubs.

mod nonce_reuse;
mod sampler_patterned_y;
mod toy_params_too_small;
mod verifier_no_ctilde;
mod verifier_no_omega;
mod verifier_no_z_bound;

pub use nonce_reuse::recover_secret_from_reused_mask;
pub use sampler_patterned_y::recover_secret_from_patterned_mask;
pub use toy_params_too_small::recover_toy_secret_by_search;
pub use verifier_no_ctilde::strict_ctilde_accepts;
pub use verifier_no_omega::strict_hint_weight_accepts;
pub use verifier_no_z_bound::strict_z_bound_accepts;

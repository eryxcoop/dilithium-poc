//! Student-facing Phase 1 exercise stubs.

mod nonce_reuse;
mod sampler_patterned_y;
mod toy_params_too_small;
mod verifier_no_ctilde;

pub use nonce_reuse::recover_secret_from_reused_mask;
pub use sampler_patterned_y::{estimate_mask_bias_means, estimate_secret_from_biased_masks};
pub use toy_params_too_small::recover_toy_secret_by_search;
pub use verifier_no_ctilde::forge_signature_without_ctilde_binding;

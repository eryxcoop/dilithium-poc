//! Student-facing exercise stubs.
//!
//! These modules are compiled only with the `exercises` feature. They contain
//! intentionally incomplete functions that correspond to the solved demos under
//! `crate::failures`.

mod eta_unbounded_secret;
mod lambda_too_short_cross_message;
mod nonce_reuse;
mod sampler_patterned_y;
mod toy_dense_hint_forgery;
mod toy_params_too_small;
mod verifier_no_ctilde;

pub use eta_unbounded_secret::estimate_secret_from_unbounded_eta;
pub use lambda_too_short_cross_message::forge_cross_message_with_short_lambda;
pub use nonce_reuse::recover_secret_from_reused_mask;
pub use sampler_patterned_y::{estimate_mask_bias_means, estimate_secret_from_biased_masks};
pub use toy_dense_hint_forgery::forge_signature_with_dense_hints;
pub use toy_params_too_small::recover_toy_secret_by_search;
pub use verifier_no_ctilde::forge_signature_without_ctilde_binding;

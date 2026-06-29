//! Student-facing cryptography exercises.
//!
//! Each module is a small break-it-yourself challenge: a broken ML-DSA-shaped
//! world, a few public artifacts, and one missing exploit.
//!
//! The functions here are intentionally incomplete. They mirror the solved
//! demos under `crate::failures`, but keep the interesting step in the
//! student's hands.
//!
//! Build with the `exercises` feature, pick a module, and make the tests go
//! green. The math is toy-sized; the mistake is the real lesson.

mod eta_unbounded_secret;
mod gamma1_beta_boundary_oracle;
mod gamma2_lowbits_boundary_oracle;
mod gamma2_lowbits_pruned_recovery;
mod lambda_too_short_cross_message;
mod nonce_reuse;
mod sampler_patterned_y;
mod toy_dense_hint_forgery;
mod toy_params_too_small;
mod verifier_no_ctilde;

pub use eta_unbounded_secret::estimate_secret_from_unbounded_eta;
pub use gamma1_beta_boundary_oracle::{
    BoundaryObservation, accepted_mask_count as boundary_accepted_mask_count,
    boundary_log_likelihood as z_boundary_log_likelihood, boundary_shift as z_boundary_shift,
    cyclic_convolution as z_boundary_cyclic_convolution, recover_secret_from_boundary_oracle,
};
pub use gamma2_lowbits_boundary_oracle::{
    LowBitsObservation, accepted_noise_count as lowbits_accepted_noise_count,
    boundary_shift as lowbits_boundary_shift, cyclic_convolution as lowbits_cyclic_convolution,
    lowbits_log_likelihood, recover_secret_from_lowbits_oracle,
};
pub use gamma2_lowbits_pruned_recovery::{
    BoundaryConstraint, PrunedLowBitsObservation,
    accepted_noise_count as pruned_lowbits_accepted_noise_count, constraint_remains_possible,
    constraints_from_observations as pruned_constraints_from_observations,
    lowbits_log_likelihood as pruned_lowbits_log_likelihood, partial_shift_range,
    recover_secret_with_pruning,
};
pub use lambda_too_short_cross_message::forge_cross_message_with_short_lambda;
pub use nonce_reuse::recover_secret_from_reused_mask;
pub use sampler_patterned_y::{estimate_mask_bias_means, estimate_secret_from_biased_masks};
pub use toy_dense_hint_forgery::forge_signature_with_dense_hints;
pub use toy_params_too_small::recover_toy_secret_by_search;
pub use verifier_no_ctilde::forge_signature_without_ctilde_binding;

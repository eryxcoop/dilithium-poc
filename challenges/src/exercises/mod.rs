//! Student-facing exercise stubs.
//!
//! These modules are compiled only with the `exercises` feature. They contain
//! intentionally incomplete functions that correspond to the solved demos under
//! `crate::failures`.

pub mod phase1;

pub use phase1::{
    estimate_mask_bias_means, estimate_secret_from_biased_masks,
    forge_signature_without_ctilde_binding, recover_secret_from_reused_mask,
    recover_toy_secret_by_search, strict_z_bound_accepts,
};

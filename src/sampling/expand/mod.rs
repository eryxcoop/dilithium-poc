//! FIPS 204 expansion algorithms built from lower-level sampling primitives.
//!
//! The rejection samplers in [`super::rejection`] produce one polynomial at a
//! time. The expansion algorithms in this module assemble those polynomials
//! into the larger ML-DSA objects used by key generation and signing:
//!
//! - `ExpandA` builds the public matrix `Â`.
//! - `ExpandS` builds the secret vectors `s1` and `s2`.
//! - `ExpandMask` builds the signing mask vector `y`.

mod a;
mod mask;
mod s;

pub use a::{expand_a, expand_a_with_limits};
pub use mask::{expand_mask, expand_mask_with_limits};
pub use s::{expand_s, expand_s_with_limits};

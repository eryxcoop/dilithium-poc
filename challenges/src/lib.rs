//! Educational ML-DSA failure challenge harness.
//!
//! This crate is a separate workspace member on purpose: vulnerable examples
//! must not live in the conformant `dilithium-poc` implementation path. The
//! safe scaffolding in this crate always compiles, while concrete vulnerable
//! runners should be gated behind the `failure-challenges` feature.

pub mod shared;
pub mod toy;

/// Student exercise stubs.
#[cfg(feature = "exercises")]
pub mod exercises;

/// Intentionally vulnerable classroom demos.
#[cfg(feature = "failure-challenges")]
pub mod failures;

/// Returns whether intentionally vulnerable challenge runners are enabled.
///
/// The toy algebra and transcript types are always available because they are
/// harmless scaffolding. Concrete examples that break FIPS 204 or RFC 9881
/// should be compiled only when this returns `true`.
pub const fn failure_challenges_enabled() -> bool {
    cfg!(feature = "failure-challenges")
}

/// Returns whether student exercise stubs are enabled.
///
/// The `exercises` feature exposes intentionally incomplete functions and
/// tests that students are expected to make pass.
pub const fn exercises_enabled() -> bool {
    cfg!(feature = "exercises")
}

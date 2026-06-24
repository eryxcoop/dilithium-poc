//! High-level ML-DSA operations from FIPS 204.
//!
//! This module wires together the lower-level milestones into the external
//! `ML-DSA.KeyGen`, `ML-DSA.Sign`, and `ML-DSA.Verify` workflows. The raw key
//! and signature encodings remain the FIPS 204 byte strings represented by
//! [`PublicKey`], [`PrivateKey`], and [`Signature`].

mod algebra;
mod context;
mod keygen;
mod sign;
mod types;
mod verify;

pub use keygen::{keygen, keygen_from_seed};
pub use sign::sign;
#[cfg(test)]
pub(crate) use sign::sign_with_randomness_for_test;
#[cfg(feature = "instrumentation")]
pub use sign::sign_with_report;
#[cfg(any(test, feature = "instrumentation"))]
pub use sign::{sign_deterministic_for_test, sign_deterministic_for_test_with_report};
pub use types::{KeyPair, PrivateKey, PublicKey, Signature, SignatureWithReport, SigningReport};
pub use verify::{verify, verify_lengths};

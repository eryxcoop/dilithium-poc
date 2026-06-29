//! High-level ML-DSA operations from FIPS 204.
//!
//! This module wires together the lower-level milestones into the external
//! `ML-DSA.KeyGen`, `ML-DSA.Sign`, and `ML-DSA.Verify` workflows. The raw key
//! and signature encodings remain the FIPS 204 byte strings represented by
//! [`PublicKey`], [`PrivateKey`], and [`Signature`].

mod context;
#[cfg(feature = "instrumentation")]
mod instrumentation;
mod keygen;
mod random;
mod sign;
mod types;
mod verify;

#[cfg(feature = "instrumentation")]
pub use instrumentation::{
    OverweightHintAttempt, find_overweight_hint_attempt,
    verify_overweight_hint_attempt_without_omega,
};
pub use keygen::KeygenSeed;
pub use types::{KeyPair, PrivateKey, PublicKey, Signature, SignatureWithReport, SigningReport};

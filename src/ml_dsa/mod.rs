//! High-level ML-DSA operations from FIPS 204.
//!
//! This module wires together the lower-level milestones into the external
//! `ML-DSA.KeyGen`, `ML-DSA.Sign`, and `ML-DSA.Verify` workflows. The raw key
//! and signature encodings remain the FIPS 204 byte strings represented by
//! [`PublicKey`], [`PrivateKey`], and [`Signature`].

mod context;
mod keygen;
mod random;
mod sign;
mod types;
mod verify;

pub use keygen::KeygenSeed;
pub use types::{KeyPair, PrivateKey, PublicKey, Signature, SignatureWithReport, SigningReport};
pub use verify::{verify, verify_lengths};

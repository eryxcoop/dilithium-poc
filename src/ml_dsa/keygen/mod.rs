//! FIPS 204 ML-DSA key generation.
//!
//! This module implements the external `ML-DSA.KeyGen()` entry point and the
//! deterministic internal `ML-DSA.KeyGen_internal(ξ)` algorithm.
//!
//! The internal flow is:
//!
//! ```text
//! (ρ, ρ′, K) = H(ξ || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
//! Â          = ExpandA(ρ)
//! (s₁, s₂)   = ExpandS(ρ′)
//! t          = Âs₁ + s₂
//! (t₁, t₀)   = Power2Round(t)
//! pk         = pkEncode(ρ, t₁)
//! tr         = H(pk, 64)
//! sk         = skEncode(ρ, K, tr, s₁, s₂, t₀)
//! ```
//!
//! The public key carries only `ρ` and `t₁`: `ρ` lets verifiers reconstruct the
//! public matrix `Â`, while `t₁` is the high-order part of `t`. The expanded
//! private key keeps the signing material `K`, `s₁`, `s₂`, and `t₀`, plus `tr`
//! so signing can compute `μ = H(tr || M′, 64)` without hashing the public key
//! again.

mod algorithm;
mod seed;

pub use seed::KeygenSeed;

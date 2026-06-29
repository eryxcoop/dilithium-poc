//! FIPS 204 ML-DSA signing.
//!
//! This module implements the external pure `ML-DSA.Sign` path. The public
//! [`PrivateKey::sign`](super::types::PrivateKey::sign) API is hedged: it
//! samples fresh 32-byte per-message randomness and feeds it into the internal
//! signing seed derivation. Deterministic entry points exist only for KATs,
//! ACVP vectors, instrumentation, and benchmarks.
//!
//! Signing starts by decoding the expanded private key:
//!
//! ```text
//! sk = skEncode(ρ, K, tr, s₁, s₂, t₀)
//! ```
//!
//! The byte-aligned external message and context are formatted as `M′` by
//! [`super::context::format_message`]. The internal representatives are then:
//!
//! ```text
//! μ  = H(tr || M′, 64)
//! ρ″ = H(K || rnd || μ, 64)
//! Â = ExpandA(ρ)
//! ```
//!
//! The rejection loop for counter `κ` is:
//!
//! ```text
//! y  = ExpandMask(ρ″, κ)
//! w  = Ây
//! w₁ = HighBits(w)
//!
//! c̃ = H(μ || w1Encode(w₁), λ/4)
//! c  = SampleInBall(c̃)
//!
//! z  = y + c·s₁
//! r₀ = LowBits(w - c·s₂)
//!
//! reject if ||z||∞  ≥ γ₁ - β
//! reject if ||r₀||∞ ≥ γ₂ - β
//!
//! reject if ||c·t₀||∞ ≥ γ₂
//! h = MakeHint(-c·t₀, w - c·s₂ + c·t₀)
//! reject if #ones(h) > ω
//!
//! sig = sigEncode(c̃, z, h)
//! ```
//!
//! Rejected attempts advance `κ` by `l`, which gives the next `ExpandMask`
//! call a distinct XOF domain. Instrumented signing records only aggregate
//! counters and sampling reports; it does not expose rejected intermediates.

mod algorithm;
mod types;

pub(crate) use types::{ChallengeSeed, MessageRepresentative};
#[cfg(feature = "instrumentation")]
pub(crate) use types::{SIGNING_RANDOMNESS_BYTES, SigningRandomness};

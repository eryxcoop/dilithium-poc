//! FIPS 204 ML-DSA verification.
//!
//! This module implements the external pure `ML-DSA.Verify` path for a
//! byte-aligned message and context. Verification reconstructs the same
//! challenge seed that signing committed to, using only the public key,
//! signature, formatted message, and context.
//!
//! The external message and context are first formatted as `M′` by
//! [`super::context::format_message`]:
//!
//! ```text
//! M′ = 0x00 || len(ctx) || ctx || M
//! ```
//!
//! The raw public key and signature are then decoded as:
//!
//! ```text
//! pk  = pkEncode(ρ, t₁)
//! sig = sigEncode(c̃, z, h)
//! ```
//!
//! Verification recomputes:
//!
//! ```text
//! Â = ExpandA(ρ)
//! tr = H(pk, 64)
//! μ  = H(tr || M′, 64)
//! c  = SampleInBall(c̃)
//! ```
//!
//! The core reconstruction is:
//!
//! ```text
//! w′  = Âz - c·t₁·2ᵈ
//! w₁′ = UseHint(h, w′)
//! c̃′ = H(μ || w1Encode(w₁′), λ/4)
//! ```
//!
//! The signature is accepted exactly when `z` is within the FIPS infinity-norm
//! bound and the recomputed challenge seed matches the encoded one:
//!
//! ```text
//! ||z||∞ < γ₁ - β
//! c̃′ == c̃
//! ```

mod algorithm;
mod types;

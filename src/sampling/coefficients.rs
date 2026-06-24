//! Coefficient and seed helpers shared by sampling algorithms.
//!
//! This module contains the small FIPS 204 building blocks that turn XOF bytes
//! into typed algebraic values. The larger algorithms in [`super::rejection`]
//! and [`super::expand`] handle loop structure and vector or matrix assembly;
//! this file handles candidate conversion, seed derivation, and `η` validation.
//!
//! The `coeff_from_*` helpers return `Option<Coefficient>` because FIPS rejection
//! sampling can reject a candidate byte pattern. `None` means "reject this
//! candidate and keep squeezing bytes," not a malformed external input.

use crate::coefficient::Coefficient;
use crate::encoding::integer_to_bytes;
use crate::error::{DilithiumError, DilithiumResult};
use crate::params::Q;
use crate::sampling::constants::{REJ_BOUNDED_POLY_SEED_BYTES, RejBoundedPolySeed};

/// Two-byte index appended to a 64-byte sampling seed.
///
/// FIPS 204 uses this suffix shape for both `ExpandS(ρ')` and
/// `ExpandMask(ρ, μ)`: the derived `RejBoundedPoly` input is
/// `seed || IntegerToBytes(index, 2)`. Keeping the suffix as a small newtype
/// makes call sites spell out when they are crossing from row/counter arithmetic
/// into the byte-level FIPS seed format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SamplingIndex(u16);

impl SamplingIndex {
    /// Builds an index from the exact 16-bit FIPS suffix value.
    pub(super) const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Builds an index from a small parameter-set dimension.
    pub(super) fn from_usize(value: usize) -> Self {
        debug_assert!(u16::try_from(value).is_ok());
        Self(value as u16)
    }

    /// Adds a vector row to a base counter using the previous wrapping behavior.
    pub(super) fn wrapping_add_usize(self, value: usize) -> Self {
        Self(self.0.wrapping_add(value as u16))
    }

    const fn value(self) -> u16 {
        self.0
    }
}

/// Derives the indexed 66-byte seed consumed by `RejBoundedPoly`.
///
/// FIPS 204 derives bounded-polynomial seeds by appending
/// `IntegerToBytes(index, 2)` to a 64-byte base seed. `ExpandS(ρ')` uses
/// indices `r` and `r + l`; `ExpandMask(ρ, μ)` uses `μ + r`.
pub(super) fn derive_indexed_bounded_seed(
    seed: [u8; 64],
    index: SamplingIndex,
) -> RejBoundedPolySeed {
    let mut derived_seed = [0u8; REJ_BOUNDED_POLY_SEED_BYTES];
    derived_seed[..seed.len()].copy_from_slice(&seed);
    derived_seed[seed.len()..].copy_from_slice(&integer_to_bytes(index.value() as u64, 2));
    RejBoundedPolySeed::new(derived_seed)
}

/// Ensures `η` is one of the FIPS 204 values supported by `CoeffFromHalfByte`.
///
/// ML-DSA parameter sets use `η = 2` or `η = 4`. Other values are outside
/// the conforming parameter sets for this POC and are rejected before sampling.
pub(super) fn ensure_supported_eta(eta: u32) -> DilithiumResult<()> {
    match eta {
        2 | 4 => Ok(()),
        _ => Err(DilithiumError::InvalidParameterSet),
    }
}

/// Implements FIPS 204 `CoeffFromThreeBytes`.
///
/// The top bit of `b2` is cleared, the three bytes are interpreted as a
/// little-endian 23-bit integer, and the candidate is accepted only when it is
/// less than `q`. Accepted values are returned as canonical [`Coefficient`]s in
/// `Z_q`; rejected candidates return `None`.
pub(super) fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<Coefficient> {
    let z = (((b2 & 0x7f) as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32);
    (z < Q).then(|| Coefficient::from(z as i32))
}

/// Implements FIPS 204 `CoeffFromHalfByte`.
///
/// For `η = 2`, nibbles `0..15` map into `[-2, 2]` and `15` is rejected.
/// For `η = 4`, nibbles `0..9` map into `[-4, 4]` and `9..16` are rejected.
/// Accepted values are returned as centered [`Coefficient`]s; rejected
/// candidates return `None`.
pub(super) fn coeff_from_half_byte(value: u8, eta: u32) -> Option<Coefficient> {
    let coefficient = match eta {
        2 if value < 15 => Some(2 - (value % 5) as i32),
        4 if value < 9 => Some(4 - value as i32),
        2 | 4 => None,
        _ => None,
    }?;
    Some(Coefficient::centered(coefficient as i64))
}

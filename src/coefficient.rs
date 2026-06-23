//! Coefficient type and modular semantics for ML-DSA.
//!
//! This module defines the public `Coefficient` newtype used by the algebraic
//! domain model. The type carries the canonical representative modulo `q` and
//! implements basic modular arithmetic through operator overloading.

use core::ops::{Add, Neg, Sub};

use crate::Q;

/// One coefficient in `Z_q` with modular arithmetic semantics.
///
/// The stored value is always the canonical representative modulo `q`, meaning
/// it always lies in the range `[0, q)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Coefficient(i32);

/// Canonical non-negative representative range for coefficients modulo `q`.
///
/// Values in canonical form lie in `[0, q)`.
pub const CANONICAL_MIN: Coefficient = Coefficient(0);

/// Largest canonical representative modulo `q`.
pub const CANONICAL_MAX: Coefficient = Coefficient((Q as i32) - 1);

/// Smallest centered representative modulo `q`.
///
/// Since `q` is odd, the centered range is symmetric:
/// `[-(q - 1) / 2, (q - 1) / 2]`.
pub const CENTERED_MIN: Coefficient = Coefficient(-(((Q as i32) - 1) / 2));

/// Largest centered representative modulo `q`.
pub const CENTERED_MAX: Coefficient = Coefficient(((Q as i32) - 1) / 2);

impl Coefficient {
    /// Returns the canonical representative of `value` modulo `q`.
    ///
    /// The result is always in the range `[0, q)`.
    pub fn canonical(value: i64) -> Self {
        Self(value.rem_euclid(Q as i64) as i32)
    }

    /// Returns the centered representative of `value` modulo `q`.
    ///
    /// The result is always in the range `[-(q - 1)/2, (q - 1)/2]`.
    pub fn centered(value: i64) -> Self {
        let canonical = Self::canonical(value);
        if canonical.0 > CENTERED_MAX.0 {
            Self(canonical.0 - Q as i32)
        } else {
            canonical
        }
    }

    /// Returns the underlying signed integer representation.
    pub fn value(self) -> i32 {
        self.0
    }

    /// Returns `true` when this coefficient is already in canonical form.
    pub fn is_canonical(self) -> bool {
        (CANONICAL_MIN.0..=CANONICAL_MAX.0).contains(&self.0)
    }

    /// Returns `true` when this coefficient is in centered form.
    pub fn is_centered(self) -> bool {
        (CENTERED_MIN.0..=CENTERED_MAX.0).contains(&self.0)
    }
}

impl Default for Coefficient {
    fn default() -> Self {
        CANONICAL_MIN
    }
}

impl Add for Coefficient {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::canonical((self.0 as i64) + (rhs.0 as i64))
    }
}

impl Sub for Coefficient {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::canonical((self.0 as i64) - (rhs.0 as i64))
    }
}

impl Neg for Coefficient {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::canonical(-(self.0 as i64))
    }
}

impl From<i32> for Coefficient {
    fn from(value: i32) -> Self {
        Self::canonical(value as i64)
    }
}

impl From<Coefficient> for i32 {
    fn from(value: Coefficient) -> Self {
        value.0
    }
}

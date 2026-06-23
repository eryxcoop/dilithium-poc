//! Rounding and decomposition helpers from FIPS 204 Section 7.4.
//!
//! These routines split one coefficient modulo `q` into a coarse component and
//! a centered remainder, but they serve different purposes in ML-DSA:
//!
//! - `Power2Round` uses a `2^d` radix and is used to split `t` during key
//!   generation into the public high part and the secret low part.
//! - `Decompose` uses a `2 * γ_2` radix and is used for the commitment and
//!   hint path behind `HighBits`, `LowBits`, `MakeHint`, and `UseHint`.
//!
//! `Decompose` also has one special wrap-around rule that `Power2Round` does
//! not have: when the straightforward decomposition would place the high part
//! on the top boundary near `q - 1`, FIPS 204 maps that case back to
//! `high = 0` and shifts the low part by `-1`.

use crate::{Coefficient, D, Q};

/// Result of `Power2Round(r)` from FIPS 204 Algorithm 35.
///
/// The pair satisfies `r = high * 2^d + low (mod q)`, where `low` is the
/// centered representative modulo `2^d`.
///
/// ML-DSA uses this decomposition for the `t = t1 * 2^d + t0` split in key
/// generation. The high part is what eventually feeds public-key encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Power2Round {
    high: u32,
    low: i32,
}

impl Power2Round {
    /// Returns the high-order component `r1`.
    pub fn high(self) -> u32 {
        self.high
    }

    /// Returns the centered low-order component `r0`.
    pub fn low(self) -> i32 {
        self.low
    }
}

/// Result of `Decompose(r)` from FIPS 204 Algorithm 36.
///
/// The pair satisfies `r = high * (2 * γ_2) + low (mod q)`, with the
/// special wrap-around rule from FIPS 204 applied when the straightforward
/// decomposition would place `high` at `(q - 1) / (2 * γ_2)`.
///
/// ML-DSA uses this decomposition for `HighBits`, `LowBits`, and later for the
/// hint machinery used during signing and verification. Unlike [`Power2Round`],
/// it is tuned for stable reconstruction near the `γ_2` boundary rather than
/// for public-key compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decomposed {
    high: u32,
    low: i32,
}

impl Decomposed {
    /// Returns the high-order component `r1`.
    pub fn high(self) -> u32 {
        self.high
    }

    /// Returns the centered low-order component `r0`.
    pub fn low(self) -> i32 {
        self.low
    }
}

impl Coefficient {
    /// Applies `Power2Round` from FIPS 204 Algorithm 35 to this coefficient.
    ///
    /// The returned pair satisfies `r = r1 * 2^d + r0 (mod q)`, where `r0`
    /// lies in the centered `mod± 2^d` interval.
    ///
    /// This is the decomposition used to compress `t` in key generation.
    pub fn power2_round(self) -> Power2Round {
        let modulus = 1i32 << D;
        let r_plus = self.canonical_value();
        let low = mod_plus_minus(r_plus, modulus);
        let high = ((r_plus - low) / modulus) as u32;

        Power2Round { high, low }
    }

    /// Applies `Decompose` from FIPS 204 Algorithm 36 to this coefficient.
    ///
    /// `γ_2` should come from one of the ML-DSA parameter sets. The
    /// returned pair satisfies `r = r1 * (2 * γ_2) + r0 (mod q)`, with the
    /// FIPS wrap-around rule for the `q - 1` boundary.
    ///
    /// Unlike [`Coefficient::power2_round`], this decomposition exists to
    /// support the commitment and hint path. If the straightforward
    /// decomposition would land on the top wrap-around boundary, FIPS 204
    /// forces `r1 = 0` and decrements `r0` by one instead.
    pub fn decompose(self, gamma2: u32) -> Decomposed {
        assert!(gamma2 > 0, "gamma2 must be positive");

        let alpha = (2 * gamma2) as i32;
        let r_plus = self.canonical_value();
        let mut low = mod_plus_minus(r_plus, alpha);
        let high = if r_plus - low == (Q as i32) - 1 {
            low -= 1;
            0
        } else {
            ((r_plus - low) / alpha) as u32
        };

        Decomposed { high, low }
    }

    /// Returns `HighBits(r)` from FIPS 204 Algorithm 37.
    ///
    /// This is the `r1` component produced by [`Coefficient::decompose`].
    ///
    /// In ML-DSA this is the stable high-order portion used in commitments and
    /// reconstructed later during verification.
    pub fn high_bits(self, gamma2: u32) -> u32 {
        self.decompose(gamma2).high()
    }

    /// Returns `LowBits(r)` from FIPS 204 Algorithm 38.
    ///
    /// This is the `r0` component produced by [`Coefficient::decompose`].
    ///
    /// In ML-DSA this is the low-order remainder checked during signing and
    /// paired with hints to preserve the correct high bits.
    pub fn low_bits(self, gamma2: u32) -> i32 {
        self.decompose(gamma2).low()
    }
}

fn mod_plus_minus(value: i32, modulus: i32) -> i32 {
    let reduced = value.rem_euclid(modulus);
    let half_floor = modulus / 2;

    if reduced > half_floor {
        reduced - modulus
    } else {
        reduced
    }
}

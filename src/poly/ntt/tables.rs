//! Internal lookup tables and small helpers for the NTT.

use std::sync::OnceLock;

use crate::coefficient::Coefficient;
use crate::params::{Q, ZETA};

static ZETAS: OnceLock<[Coefficient; 256]> = OnceLock::new();

/// Returns the cached `zetas[0..255]` table used by the FIPS 204 NTT.
pub(super) fn zetas_table() -> &'static [Coefficient; 256] {
    ZETAS.get_or_init(build_zetas_table)
}

/// Returns `256^{-1} mod q`, used at the end of the inverse NTT.
pub(super) fn inverse_of_n() -> Coefficient {
    Coefficient::from(8_347_681)
}

fn build_zetas_table() -> [Coefficient; 256] {
    let mut zetas = [Coefficient::default(); 256];
    let mut m = 1usize;
    while m < 256 {
        zetas[m] =
            Coefficient::canonical(pow_mod(ZETA as i64, (m as u8).reverse_bits() as u32) as i64);
        m += 1;
    }
    zetas
}

fn pow_mod(mut base: i64, mut exponent: u32) -> i32 {
    let modulus = Q as i64;
    let mut result = 1i64;
    base = base.rem_euclid(modulus);

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base).rem_euclid(modulus);
        }
        base = (base * base).rem_euclid(modulus);
        exponent >>= 1;
    }

    result as i32
}

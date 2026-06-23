//! Shared validation helpers for raw FIPS 204 wrapper types.

use crate::error::{Error, Result};

/// Checks that a raw byte string has the exact expected FIPS 204 length.
pub(crate) fn ensure_len(item: &'static str, expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual,
            item,
        })
    }
}

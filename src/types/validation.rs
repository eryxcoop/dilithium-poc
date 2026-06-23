//! Shared validation helpers for raw FIPS 204 wrapper types.

use crate::error::{DilithiumError, DilithiumResult};

/// Checks that a raw byte string has the exact expected FIPS 204 length.
pub(crate) fn ensure_len(
    item: &'static str,
    expected: usize,
    actual: usize,
) -> DilithiumResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DilithiumError::InvalidLength {
            expected,
            actual,
            item,
        })
    }
}

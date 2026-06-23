//! Shared validation helpers for polynomial containers.

use crate::error::{DilithiumError, DilithiumResult};

/// Checks that a polynomial container received the exact expected item count.
pub(crate) fn ensure_item_len(
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

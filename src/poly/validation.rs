//! Shared validation helpers for polynomial containers.

use crate::error::{Error, Result};

/// Checks that a polynomial container received the exact expected item count.
pub(crate) fn ensure_item_len(item: &'static str, expected: usize, actual: usize) -> Result<()> {
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

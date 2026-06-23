//! Shared validation helpers for crate-internal APIs.

use crate::error::{DilithiumError, DilithiumResult};

/// Checks that a byte string or item sequence has the exact expected length.
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

/// Checks that a vector-like domain object has the expected dimension.
pub(crate) fn ensure_dimension(
    item: &'static str,
    expected: usize,
    actual: usize,
) -> DilithiumResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(DilithiumError::DimensionMismatch {
            expected,
            actual,
            item,
        })
    }
}

/// Checks that an unsigned integer lies within an inclusive range.
pub(crate) fn ensure_u32_range(
    item: &'static str,
    value: u32,
    min: u32,
    max: u32,
) -> DilithiumResult<()> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(DilithiumError::ValueOutOfRange {
            item,
            min: min as i64,
            max: max as i64,
            actual: value as i64,
        })
    }
}

/// Checks that a signed integer lies within an inclusive range.
pub(crate) fn ensure_i32_range(
    item: &'static str,
    value: i32,
    min: i32,
    max: i32,
) -> DilithiumResult<()> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(DilithiumError::ValueOutOfRange {
            item,
            min: min as i64,
            max: max as i64,
            actual: value as i64,
        })
    }
}

/// Checks that an unsigned bound is strictly positive.
pub(crate) fn ensure_positive_u32_bound(item: &'static str, bound: u32) -> DilithiumResult<()> {
    if bound > 0 {
        Ok(())
    } else {
        Err(DilithiumError::ValueOutOfRange {
            item,
            min: 1,
            max: i64::from(u32::MAX),
            actual: 0,
        })
    }
}

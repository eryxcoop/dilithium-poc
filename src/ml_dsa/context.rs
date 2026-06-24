//! External ML-DSA message formatting.

use crate::error::{DilithiumError, DilithiumResult};

const PURE_ML_DSA_DOMAIN_SEPARATOR: u8 = 0;
const MAX_CONTEXT_BYTES: usize = 255;

/// Formats `M'` for pure ML-DSA signing and verification.
///
/// FIPS 204 Algorithms 2 and 3 prepend
/// `IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx` before the
/// message. The standard describes `M'` as a bit string; this POC accepts
/// byte-aligned messages, so the equivalent byte string is passed directly into
/// SHAKE256 by the internal algorithms.
pub(crate) fn format_message(message: &[u8], context: &[u8]) -> DilithiumResult<Vec<u8>> {
    ensure_context_len(context)?;

    let mut formatted = Vec::with_capacity(2 + context.len() + message.len());
    formatted.push(PURE_ML_DSA_DOMAIN_SEPARATOR);
    formatted.push(context.len() as u8);
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(message);
    Ok(formatted)
}

pub(crate) fn ensure_context_len(context: &[u8]) -> DilithiumResult<()> {
    if context.len() <= MAX_CONTEXT_BYTES {
        Ok(())
    } else {
        Err(DilithiumError::InvalidLength {
            expected: MAX_CONTEXT_BYTES,
            actual: context.len(),
            item: "context",
        })
    }
}

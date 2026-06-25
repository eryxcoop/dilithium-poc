//! Counting wrapper for incremental XOF readers.
//!
//! FIPS 204 rejection samplers consume SHAKE output incrementally: the amount
//! of data needed is not always known before sampling starts. This wrapper
//! keeps that byte stream logic separate from the sampling algorithms by:
//!
//! - reading bytes from a SHAKE `XofReader`,
//! - counting how many bytes have been consumed, and
//! - enforcing an optional Table 3 XOF-byte cap.
//!
//! A `None` byte limit means "unlimited." If a read would exceed an enabled
//! cap, the wrapper returns [`DilithiumError::SamplingLimitExceeded`] before
//! consuming any additional bytes.

use shake::digest::XofReader;

use crate::error::{DilithiumError, DilithiumResult};

/// Incremental XOF reader that counts bytes and enforces an optional cap.
///
/// The `algorithm` label is carried only for diagnostics so limit errors can
/// name the sampler that exceeded its XOF-byte budget, such as `RejNTTPoly` or
/// `SampleInBall`.
pub(super) struct CountingXof<R> {
    algorithm: &'static str,
    byte_limit: Option<usize>,
    bytes_read: usize,
    reader: R,
}

impl<R: XofReader> CountingXof<R> {
    /// Wraps an incremental XOF reader with an optional byte limit.
    pub(super) fn new(algorithm: &'static str, reader: R, byte_limit: Option<usize>) -> Self {
        Self {
            algorithm,
            byte_limit,
            bytes_read: 0,
            reader,
        }
    }

    /// Returns how many bytes have been consumed from the XOF so far.
    pub(super) fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Reads exactly one byte from the XOF.
    pub(super) fn squeeze_byte(&mut self) -> DilithiumResult<u8> {
        Ok(self.squeeze_array::<1>()?[0])
    }

    /// Reads `byte_len` bytes from the XOF after checking the byte cap.
    ///
    /// The limit check happens before the underlying reader is consumed. If
    /// `bytes_read + byte_len` would exceed `byte_limit`, this returns
    /// [`DilithiumError::SamplingLimitExceeded`] and leaves the wrapped reader
    /// untouched for this attempted read.
    pub(super) fn squeeze_vec(&mut self, byte_len: usize) -> DilithiumResult<Vec<u8>> {
        let next_total =
            self.bytes_read
                .checked_add(byte_len)
                .ok_or(DilithiumError::SamplingLimitExceeded {
                    algorithm: self.algorithm,
                    limit_kind: "xof bytes",
                    limit: usize::MAX,
                })?;

        if let Some(limit) = self.byte_limit
            && next_total > limit
        {
            return Err(DilithiumError::SamplingLimitExceeded {
                algorithm: self.algorithm,
                limit_kind: "xof bytes",
                limit,
            });
        }

        let mut bytes = vec![0u8; byte_len];
        self.reader.read(&mut bytes);
        self.bytes_read = next_total;
        Ok(bytes)
    }

    /// Reads exactly `NBYTES` bytes from the XOF into a fixed-size array.
    pub(super) fn squeeze_array<const NBYTES: usize>(&mut self) -> DilithiumResult<[u8; NBYTES]> {
        let bytes = self.squeeze_vec(NBYTES)?;
        let mut out = [0u8; NBYTES];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xof::shake256_reader;

    #[test]
    fn squeeze_vec_fails_before_exceeding_xof_byte_cap() {
        let mut reader = CountingXof::new("RejBoundedPoly", shake256_reader(&[0u8; 66]), Some(2));

        reader.squeeze_vec(2).unwrap();
        let error = reader.squeeze_byte().unwrap_err();

        assert_eq!(reader.bytes_read(), 2);
        assert_eq!(
            error,
            DilithiumError::SamplingLimitExceeded {
                algorithm: "RejBoundedPoly",
                limit_kind: "xof bytes",
                limit: 2,
            }
        );
    }
}

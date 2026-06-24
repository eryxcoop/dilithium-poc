//! Sampling instrumentation report types.
//!
//! These reports are lightweight observability values for tests, benchmarks,
//! and future diagnostics. They intentionally contain only aggregate counters:
//! loop iterations, XOF bytes, and rejected-candidate counts. They do not expose
//! sampled candidates, rejected intermediate values, or any per-attempt signing
//! material.
//!
//! When these samplers are used from signing code, treat [`SamplingReport`] as
//! instrumentation rather than a security API. It is useful for confirming
//! Table 3 behavior and benchmark profiles, but it should not become a channel
//! for leaking details of rejected signing attempts.

/// Aggregate instrumentation for one sampling procedure.
///
/// The counters are intentionally coarse. For example, `RejBoundedPoly` counts
/// one loop iteration per squeezed byte, while its rejection counter is per
/// rejected nibble.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SamplingReport {
    /// Number of loop iterations counted for the procedure's Table 3 limit.
    loop_iterations: usize,
    /// Number of bytes extracted from the underlying XOF.
    xof_bytes: usize,
    /// Number of rejected candidates during rejection sampling.
    rejections: usize,
}

impl SamplingReport {
    /// Returns the number of loop iterations counted for the Table 3 limit.
    pub fn loop_iterations(self) -> usize {
        self.loop_iterations
    }

    /// Returns the number of bytes extracted from the underlying XOF.
    pub fn xof_bytes(self) -> usize {
        self.xof_bytes
    }

    /// Returns the number of rejected candidates during rejection sampling.
    pub fn rejections(self) -> usize {
        self.rejections
    }

    pub(super) fn record_loop_iteration(&mut self) {
        self.loop_iterations += 1;
    }

    pub(super) fn record_rejection(&mut self) {
        self.rejections += 1;
    }

    pub(super) fn set_xof_bytes(&mut self, xof_bytes: usize) {
        self.xof_bytes = xof_bytes;
    }

    pub(super) fn add_xof_bytes(&mut self, xof_bytes: usize) {
        self.xof_bytes += xof_bytes;
    }

    pub(crate) fn absorb(&mut self, other: Self) {
        self.loop_iterations += other.loop_iterations;
        self.xof_bytes += other.xof_bytes;
        self.rejections += other.rejections;
    }
}

/// A sampled value together with its instrumentation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sampled<T> {
    /// The sampled value.
    value: T,
    /// Instrumentation collected while generating `value`.
    report: SamplingReport,
}

impl<T> Sampled<T> {
    pub(super) fn new(value: T, report: SamplingReport) -> Self {
        Self { value, report }
    }

    /// Returns the sampled value by reference.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns the sampling instrumentation report.
    pub fn report(&self) -> SamplingReport {
        self.report
    }

    /// Consumes the wrapper and returns the sampled value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Consumes the wrapper and returns both value and report.
    pub fn into_parts(self) -> (T, SamplingReport) {
        (self.value, self.report)
    }
}

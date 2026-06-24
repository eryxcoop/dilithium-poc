//! Public wrapper and report types for high-level ML-DSA operations.

mod private_key;
mod public_key;
mod signature;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;

use crate::sampling::SamplingReport;

/// Raw FIPS 204 public/private key pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl KeyPair {
    pub(crate) fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Returns the raw FIPS 204 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the raw FIPS 204 expanded private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Consumes the pair and returns `(public_key, private_key)`.
    pub fn into_parts(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }
}

/// Aggregate signing-loop instrumentation.
///
/// This report is intended for tests and benchmarks that need to observe the
/// distribution of rejection-loop repetitions. It intentionally contains only
/// aggregate counters and one aggregated [`SamplingReport`]; it does not expose
/// rejected vectors, challenges, or per-attempt secrets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SigningReport {
    attempts: usize,
    rejected_by_z_or_r0: usize,
    rejected_by_ct0_or_hints: usize,
    sampling: SamplingReport,
}

impl SigningReport {
    pub(crate) fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    pub(crate) fn record_z_or_r0_rejection(&mut self) {
        self.rejected_by_z_or_r0 += 1;
    }

    pub(crate) fn record_ct0_or_hint_rejection(&mut self) {
        self.rejected_by_ct0_or_hints += 1;
    }

    pub(crate) fn absorb_sampling(&mut self, report: SamplingReport) {
        self.sampling.absorb(report);
    }

    /// Returns the number of signing-loop attempts.
    pub fn attempts(self) -> usize {
        self.attempts
    }

    /// Returns how many attempts failed the `z` or `r0` infinity-norm checks.
    pub fn rejected_by_z_or_r0(self) -> usize {
        self.rejected_by_z_or_r0
    }

    /// Returns how many attempts failed the `c t0` norm or hint-weight checks.
    pub fn rejected_by_ct0_or_hints(self) -> usize {
        self.rejected_by_ct0_or_hints
    }

    /// Returns the aggregated sampling report from `ExpandMask` and `SampleInBall`.
    pub fn sampling(self) -> SamplingReport {
        self.sampling
    }
}

/// A signature together with aggregate signing instrumentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureWithReport {
    signature: Signature,
    report: SigningReport,
}

impl SignatureWithReport {
    pub(crate) fn new(signature: Signature, report: SigningReport) -> Self {
        Self { signature, report }
    }

    /// Returns the generated signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns aggregate signing-loop instrumentation.
    pub fn report(&self) -> SigningReport {
        self.report
    }

    /// Consumes the wrapper and returns the signature.
    pub fn into_signature(self) -> Signature {
        self.signature
    }

    /// Consumes the wrapper and returns `(signature, report)`.
    pub fn into_parts(self) -> (Signature, SigningReport) {
        (self.signature, self.report)
    }
}

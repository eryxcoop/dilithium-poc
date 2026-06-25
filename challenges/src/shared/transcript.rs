//! Classroom-friendly transcript format for challenge runners.
//!
//! Challenge runners should be deterministic under fixed seeds and should emit
//! a transcript that explains the bug, the exploit handle, and the FIPS defense.
//! Tests can assert on the same [`ChallengeRun`] object that examples print.

use core::fmt::{self, Display, Formatter};

/// Describes what kind of environment a challenge uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeMode {
    /// The demo uses reduced educational parameters.
    ToyParams,
    /// The demo uses one of the real ML-DSA parameter sets in a controlled way.
    RealParams,
    /// The demo targets parsing, encoding, DER, or protocol binding.
    ParserOrProtocol,
}

impl Display for ChallengeMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToyParams => f.write_str("toy params"),
            Self::RealParams => f.write_str("real params"),
            Self::ParserOrProtocol => f.write_str("parser/protocol"),
        }
    }
}

/// Stable metadata for one challenge runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeMetadata {
    /// Machine-readable challenge id, for example `nonce_reuse`.
    pub id: &'static str,
    /// Human-readable challenge title.
    pub title: &'static str,
    /// Whether the demo uses toy parameters, real parameters, or parser data.
    pub mode: ChallengeMode,
    /// FIPS 204 or RFC 9881 rule intentionally violated by the vulnerable path.
    pub broken_rule: &'static str,
}

impl ChallengeMetadata {
    /// Creates challenge metadata.
    pub const fn new(
        id: &'static str,
        title: &'static str,
        mode: ChallengeMode,
        broken_rule: &'static str,
    ) -> Self {
        Self {
            id,
            title,
            mode,
            broken_rule,
        }
    }
}

/// One line item in a rendered challenge transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptStep {
    title: String,
    body: String,
}

impl TranscriptStep {
    /// Creates a transcript step.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
        }
    }

    /// Returns the step title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the step body.
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// Ordered classroom transcript emitted by a challenge runner.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transcript {
    steps: Vec<TranscriptStep>,
}

impl Transcript {
    /// Creates an empty transcript.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one step and returns the transcript for chaining.
    pub fn step(mut self, title: impl Into<String>, body: impl Into<String>) -> Self {
        self.steps.push(TranscriptStep::new(title, body));
        self
    }

    /// Appends one step in place.
    pub fn push(&mut self, title: impl Into<String>, body: impl Into<String>) {
        self.steps.push(TranscriptStep::new(title, body));
    }

    /// Returns all transcript steps.
    pub fn steps(&self) -> &[TranscriptStep] {
        &self.steps
    }

    /// Returns `true` if there are no transcript steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Result object shared by examples and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeRun {
    metadata: ChallengeMetadata,
    transcript: Transcript,
    success: bool,
}

impl ChallengeRun {
    /// Creates a challenge run result.
    pub fn new(metadata: ChallengeMetadata, transcript: Transcript, success: bool) -> Self {
        Self {
            metadata,
            transcript,
            success,
        }
    }

    /// Returns the challenge metadata.
    pub fn metadata(&self) -> &ChallengeMetadata {
        &self.metadata
    }

    /// Returns the emitted transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    /// Returns `true` when the exploit or failure demonstration succeeded.
    pub fn success(&self) -> bool {
        self.success
    }

    /// Renders a stable classroom transcript.
    pub fn render(&self) -> String {
        let mut output = String::new();
        output.push_str("# ");
        output.push_str(self.metadata.title);
        output.push('\n');
        output.push_str("id: ");
        output.push_str(self.metadata.id);
        output.push('\n');
        output.push_str("mode: ");
        output.push_str(&self.metadata.mode.to_string());
        output.push('\n');
        output.push_str("broken rule: ");
        output.push_str(self.metadata.broken_rule);
        output.push_str("\n\n");

        for (index, step) in self.transcript.steps().iter().enumerate() {
            output.push_str(&(index + 1).to_string());
            output.push_str(". ");
            output.push_str(step.title());
            output.push('\n');
            output.push_str(step.body());
            output.push_str("\n\n");
        }

        output.push_str("result: ");
        output.push_str(if self.success { "success" } else { "failed" });
        output.push('\n');
        output
    }
}

impl Display for ChallengeRun {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

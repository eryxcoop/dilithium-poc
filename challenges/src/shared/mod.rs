//! Shared runner and transcript utilities for challenge demos.

mod rng;
mod stats;
mod transcript;

pub use rng::SplitMix64;
pub use stats::rounded_prefix;
pub use transcript::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript, TranscriptStep};

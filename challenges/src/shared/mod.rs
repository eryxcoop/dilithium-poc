//! Shared runner and transcript utilities for challenge demos.

mod rng;
mod stats;
mod toy_challenge;
mod toy_search;
mod transcript;
mod truncated_challenge;

pub use rng::SplitMix64;
pub use stats::rounded_prefix;
pub use toy_challenge::{sample_ternary_seed, toy_u8_challenge_seed, toy_u8_message_representative};
pub use toy_search::random_bounded_polys;
pub use transcript::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript, TranscriptStep};
pub use truncated_challenge::{
    TOY_MESSAGE_REPRESENTATIVE_BYTES, short_prefix_24, toy_full_challenge_seed,
    toy_message_representative,
};

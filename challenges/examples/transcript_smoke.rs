//! Minimal example showing the transcript format used by vulnerable runners.
//!
//! This example is gated by `failure-challenges` even though it is harmless, so
//! the command shape matches future intentionally vulnerable demos.

use dilithium_poc_challenges::shared::{
    ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript,
};

fn main() {
    let metadata = ChallengeMetadata::new(
        "transcript_smoke",
        "Transcript Smoke Test",
        ChallengeMode::ToyParams,
        "no FIPS rule is broken; this is only the runner format",
    );
    let transcript = Transcript::new()
        .step("Setup", "Construct deterministic toy inputs.")
        .step(
            "Lesson",
            "Future runners print the exploit path in this format.",
        );

    let run = ChallengeRun::new(metadata, transcript, true);
    print!("{}", run.render());
}

//! Prints all Phase 1 failure-challenge transcripts.

use dilithium_poc_challenges::failures::phase1::phase1_runs;

fn main() {
    for run in phase1_runs() {
        println!("{}", run.render());
    }
}

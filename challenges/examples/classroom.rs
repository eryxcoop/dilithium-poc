//! Prints all classroom failure-challenge transcripts.

use dilithium_poc_challenges::failures::challenge_runs;

fn main() {
    for run in challenge_runs() {
        println!("{}", run.render());
    }
}

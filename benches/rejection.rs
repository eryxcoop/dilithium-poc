use std::collections::BTreeMap;
use std::time::Instant;

use dilithium_poc::ml_dsa::{KeyPair, sign_deterministic_for_test_with_report};
use dilithium_poc::params::{PARAMETER_SETS, ParameterSet};

const SAMPLES_PER_SET: usize = 128;

fn main() {
    println!("# M7 signing rejection benchmark");
    println!();
    println!("Samples per parameter set: {SAMPLES_PER_SET}");
    println!(
        "| Parameter set | Mean attempts | Min | Max | z/r0 rejects | c*t0/hint rejects | Sampling rejections | Histogram | Elapsed |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |");

    for parameter_set in PARAMETER_SETS {
        let started = Instant::now();
        let stats = measure(parameter_set);
        println!(
            "| {} | {:.2} | {} | {} | {} | {} | {} | `{}` | {:.2?} |",
            parameter_set.name,
            stats.mean_attempts(),
            stats.min_attempts,
            stats.max_attempts,
            stats.rejected_by_z_or_r0,
            stats.rejected_by_ct0_or_hints,
            stats.sampling_rejections,
            stats.histogram_markdown(),
            started.elapsed(),
        );
    }
}

fn measure(parameter_set: ParameterSet) -> RejectionStats {
    let key_pair = KeyPair::generate_from_seed(parameter_set, seed_for(parameter_set, 1)).unwrap();
    let mut stats = RejectionStats::default();

    for sample in 0..SAMPLES_PER_SET {
        let message = format!("M7 rejection sample {} #{sample}", parameter_set.name);
        let signed = sign_deterministic_for_test_with_report(
            key_pair.private_key(),
            message.as_bytes(),
            b"m7",
        )
        .unwrap();
        stats.record(signed.report());
    }

    stats
}

fn seed_for(parameter_set: ParameterSet, stream: u8) -> [u8; 32] {
    core::array::from_fn(|index| {
        parameter_set
            .security_category
            .wrapping_mul(47)
            .wrapping_add(stream)
            .wrapping_add(index as u8)
    })
}

#[derive(Clone, Debug, Default)]
struct RejectionStats {
    samples: usize,
    total_attempts: usize,
    min_attempts: usize,
    max_attempts: usize,
    rejected_by_z_or_r0: usize,
    rejected_by_ct0_or_hints: usize,
    sampling_rejections: usize,
    histogram: BTreeMap<usize, usize>,
}

impl RejectionStats {
    fn record(&mut self, report: dilithium_poc::ml_dsa::SigningReport) {
        let attempts = report.attempts();
        self.samples += 1;
        self.total_attempts += attempts;
        self.min_attempts = if self.samples == 1 {
            attempts
        } else {
            self.min_attempts.min(attempts)
        };
        self.max_attempts = self.max_attempts.max(attempts);
        self.rejected_by_z_or_r0 += report.rejected_by_z_or_r0();
        self.rejected_by_ct0_or_hints += report.rejected_by_ct0_or_hints();
        self.sampling_rejections += report.sampling().rejections();
        *self.histogram.entry(attempts).or_default() += 1;
    }

    fn mean_attempts(&self) -> f64 {
        self.total_attempts as f64 / self.samples as f64
    }

    fn histogram_markdown(&self) -> String {
        self.histogram
            .iter()
            .map(|(attempts, count)| format!("{attempts}:{count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

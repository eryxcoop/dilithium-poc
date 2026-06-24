use std::collections::BTreeMap;
use std::time::Instant;

use dilithium_poc::ml_dsa::{keygen_from_seed, sign_with_report};
use dilithium_poc::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ParameterSet};

const SAMPLES_PER_SET: usize = 1_024;

fn main() {
    println!("# ML-DSA signing-loop repetitions");
    println!();
    println!("Samples per parameter set: {SAMPLES_PER_SET}");
    println!();
    println!("| Parameter set | FIPS expected | Mean attempts | Min | Max | Histogram | Elapsed |");
    println!("| --- | ---: | ---: | ---: | ---: | --- | ---: |");

    for (parameter_set, expected) in [
        (ML_DSA_44, 4.25_f64),
        (ML_DSA_65, 5.1_f64),
        (ML_DSA_87, 3.85_f64),
    ] {
        let started = Instant::now();
        let stats = measure(parameter_set);
        let elapsed = started.elapsed();

        println!(
            "| {} | {:.2} | {:.2} | {} | {} | `{}` | {:.2?} |",
            parameter_set.name,
            expected,
            stats.mean(),
            stats.min,
            stats.max,
            stats.histogram_markdown(),
            elapsed,
        );
    }
}

fn measure(parameter_set: ParameterSet) -> RepetitionStats {
    let key_pair = keygen_from_seed(parameter_set, seed_for(parameter_set.security_category, 0))
        .expect("fixed keygen seed should produce a key pair");
    let mut stats = RepetitionStats::default();

    for sample in 0..SAMPLES_PER_SET {
        let message = format!("signing repetition sample {} #{sample}", parameter_set.name);
        let signed = sign_with_report(key_pair.private_key(), message.as_bytes(), b"bench")
            .expect("bench signing should succeed");
        stats.record(signed.report().attempts());
    }

    stats
}

fn seed_for(category: u8, stream: u8) -> [u8; 32] {
    core::array::from_fn(|index| {
        category
            .wrapping_mul(17)
            .wrapping_add(stream)
            .wrapping_add(index as u8)
    })
}

#[derive(Clone, Debug, Default)]
struct RepetitionStats {
    samples: usize,
    total: usize,
    min: usize,
    max: usize,
    histogram: BTreeMap<usize, usize>,
}

impl RepetitionStats {
    fn record(&mut self, attempts: usize) {
        self.samples += 1;
        self.total += attempts;
        self.min = if self.samples == 1 {
            attempts
        } else {
            self.min.min(attempts)
        };
        self.max = self.max.max(attempts);
        *self.histogram.entry(attempts).or_default() += 1;
    }

    fn mean(&self) -> f64 {
        self.total as f64 / self.samples as f64
    }

    fn histogram_markdown(&self) -> String {
        self.histogram
            .iter()
            .map(|(attempts, count)| format!("{attempts}:{count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

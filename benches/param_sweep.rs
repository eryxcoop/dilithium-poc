use std::time::Instant;

use dilithium_poc::coefficient::Coefficient;
use dilithium_poc::params::{CoreParams, EncodedSizes, ML_DSA_44, ParameterSet};
use dilithium_poc::poly::PolyVector;
use dilithium_poc::sampling::{ExpandMaskSeed, expand_mask, sample_in_ball};

const SAMPLES_PER_VARIANT: usize = 32;

fn main() {
    println!("# M7 experimental parameter sweep");
    println!();
    println!("This experiment uses non-standard parameter metadata under `experimental-params`.");
    println!("It is not ML-DSA FIPS conformance evidence.");
    println!();
    println!(
        "| Variant | gamma1 | gamma2 | tau | omega | sig bytes | Mean y norm | Mean challenge weight | Elapsed |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");

    for parameter_set in variants() {
        let started = Instant::now();
        let stats = measure(parameter_set);
        println!(
            "| {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2?} |",
            parameter_set.name,
            parameter_set.core.gamma1,
            parameter_set.core.gamma2,
            parameter_set.core.tau,
            parameter_set.core.omega,
            parameter_set.sizes.signature_bytes,
            stats.mean_y_norm(),
            stats.mean_challenge_weight(),
            started.elapsed(),
        );
    }
}

fn variants() -> Vec<ParameterSet> {
    let base = ML_DSA_44.core;
    vec![
        experimental("ML-DSA-44/base-metadata", base),
        experimental(
            "ML-DSA-44/gamma1-half",
            CoreParams {
                gamma1: base.gamma1 / 2,
                ..base
            },
        ),
        experimental(
            "ML-DSA-44/gamma2-wide",
            CoreParams {
                gamma2: base.gamma2 * 2,
                ..base
            },
        ),
        experimental(
            "ML-DSA-44/tau-plus-8",
            CoreParams {
                tau: base.tau + 8,
                ..base
            },
        ),
        experimental(
            "ML-DSA-44/omega-half",
            CoreParams {
                omega: base.omega / 2,
                ..base
            },
        ),
    ]
}

fn experimental(name: &'static str, core: CoreParams) -> ParameterSet {
    let placeholder = ParameterSet::new_experimental(name, 0, core, ML_DSA_44.sizes);
    let sizes = EncodedSizes {
        public_key_bytes: placeholder.derived_public_key_bytes(),
        private_key_bytes: placeholder.derived_private_key_bytes(),
        signature_bytes: placeholder.derived_signature_bytes(),
    };
    ParameterSet::new_experimental(name, 0, core, sizes)
}

fn measure(parameter_set: ParameterSet) -> SweepStats {
    let mut stats = SweepStats::default();

    for sample in 0..SAMPLES_PER_VARIANT {
        let mask = expand_mask(
            ExpandMaskSeed::new(seed64(sample as u8)),
            sample as u16,
            parameter_set,
        )
        .unwrap();
        let challenge_seed = vec![sample as u8; parameter_set.challenge_bytes()];
        let challenge = sample_in_ball(&challenge_seed, parameter_set).unwrap();

        stats.record(y_norm(&mask), challenge_weight(&challenge));
    }

    stats
}

fn seed64(stream: u8) -> [u8; 64] {
    core::array::from_fn(|index| stream.wrapping_mul(13).wrapping_add(index as u8))
}

fn y_norm(vector: &PolyVector) -> usize {
    vector
        .iter()
        .flat_map(|poly| poly.iter())
        .map(|coefficient| {
            Coefficient::centered(coefficient.value() as i64)
                .value()
                .unsigned_abs() as usize
        })
        .max()
        .unwrap_or_default()
}

fn challenge_weight(vector: &dilithium_poc::poly::Poly) -> usize {
    vector
        .iter()
        .filter(|coefficient| coefficient.value() != 0)
        .count()
}

#[derive(Clone, Debug, Default)]
struct SweepStats {
    samples: usize,
    total_y_norm: usize,
    total_challenge_weight: usize,
}

impl SweepStats {
    fn record(&mut self, y_norm: usize, challenge_weight: usize) {
        self.samples += 1;
        self.total_y_norm += y_norm;
        self.total_challenge_weight += challenge_weight;
    }

    fn mean_y_norm(&self) -> f64 {
        self.total_y_norm as f64 / self.samples as f64
    }

    fn mean_challenge_weight(&self) -> f64 {
        self.total_challenge_weight as f64 / self.samples as f64
    }
}

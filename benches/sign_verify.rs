use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dilithium_poc::ml_dsa::KeyPair;
use dilithium_poc::params::{PARAMETER_SETS, ParameterSet};

fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_millis(500))
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_keygen_from_seed");

    for parameter_set in PARAMETER_SETS {
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                b.iter(|| {
                    KeyPair::generate_from_seed(ps, seed_for(ps, 1)).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_sign_deterministic");

    for parameter_set in PARAMETER_SETS {
        let key_pair =
            KeyPair::generate_from_seed(parameter_set, seed_for(parameter_set, 2)).unwrap();
        let message = message_for(parameter_set);
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &_ps| {
                b.iter(|| {
                    black_box(key_pair.private_key())
                        .sign_deterministic_for_test(black_box(&message), black_box(b"m7"))
                        .unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_sign_with_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_sign_deterministic_with_report");

    for parameter_set in PARAMETER_SETS {
        let key_pair =
            KeyPair::generate_from_seed(parameter_set, seed_for(parameter_set, 3)).unwrap();
        let message = message_for(parameter_set);
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &_ps| {
                b.iter(|| {
                    black_box(key_pair.private_key())
                        .sign_deterministic_for_test_with_report(
                            black_box(&message),
                            black_box(b"m7"),
                        )
                        .unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_verify");

    for parameter_set in PARAMETER_SETS {
        let key_pair =
            KeyPair::generate_from_seed(parameter_set, seed_for(parameter_set, 4)).unwrap();
        let message = message_for(parameter_set);
        let signature = key_pair
            .private_key()
            .sign_deterministic_for_test(&message, b"m7")
            .unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &_ps| {
                b.iter(|| {
                    black_box(key_pair.public_key()).verify(
                        black_box(&message),
                        black_box(&signature),
                        black_box(b"m7"),
                    );
                });
            },
        );
    }

    group.finish();
}

fn seed_for(parameter_set: ParameterSet, stream: u8) -> [u8; 32] {
    core::array::from_fn(|index| {
        parameter_set
            .security_category
            .wrapping_mul(31)
            .wrapping_add(stream)
            .wrapping_add(index as u8)
    })
}

fn message_for(parameter_set: ParameterSet) -> Vec<u8> {
    format!(
        "M7 sign/verify benchmark message for {}",
        parameter_set.name
    )
    .into_bytes()
}

criterion_group! {
    name = benches;
    config = criterion();
    targets = bench_keygen, bench_sign, bench_sign_with_report, bench_verify
}
criterion_main!(benches);

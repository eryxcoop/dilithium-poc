use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dilithium_poc::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, PARAMETER_SETS};
use dilithium_poc::sampling::{
    ExpandASeed, ExpandMaskSeed, ExpandSSeed, expand_a, expand_mask, expand_s, sample_in_ball,
};

fn bench_expand_a(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_a");

    for parameter_set in PARAMETER_SETS {
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandASeed::new([ps.security_category; 32]);
                b.iter(|| {
                    expand_a(seed, ps).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_expand_s(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_s");

    for parameter_set in PARAMETER_SETS {
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandSSeed::new([ps.security_category; 64]);
                b.iter(|| {
                    expand_s(seed, ps).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_expand_mask(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_mask");

    for parameter_set in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandMaskSeed::new([ps.security_category + 10; 64]);
                b.iter(|| {
                    expand_mask(seed, 23, ps).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_sample_in_ball(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_in_ball");

    for parameter_set in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = vec![ps.security_category + 20; ps.challenge_bytes()];
                b.iter(|| {
                    sample_in_ball(&seed, ps).unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_expand_a,
    bench_expand_s,
    bench_expand_mask,
    bench_sample_in_ball
);
criterion_main!(benches);

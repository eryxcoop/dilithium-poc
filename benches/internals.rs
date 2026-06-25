use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use dilithium_poc::coefficient::Coefficient;
use dilithium_poc::encoding::{
    pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode,
};
use dilithium_poc::ml_dsa::{KeyPair, sign_deterministic_for_test};
use dilithium_poc::params::{PARAMETER_SETS, ParameterSet};
use dilithium_poc::pkix::{
    PkixPrivateKey, decode_subject_public_key_info, encode_one_asymmetric_key,
    parse_one_asymmetric_key, subject_public_key_info_der,
};
use dilithium_poc::poly::{Poly, PolyVector};
use dilithium_poc::sampling::{
    ExpandASeed, ExpandMaskSeed, ExpandSSeed, expand_a, expand_mask, expand_s, sample_in_ball,
};

fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_millis(500))
}

fn bench_ntt(c: &mut Criterion) {
    let poly = deterministic_poly(17);
    let ntt = poly.ntt();
    let rhs = deterministic_poly(29).ntt();

    c.bench_function("m7_ntt/forward", |b| {
        b.iter(|| {
            black_box(&poly).ntt();
        });
    });
    c.bench_function("m7_ntt/inverse", |b| {
        b.iter(|| {
            black_box(&ntt).inverse_ntt();
        });
    });
    c.bench_function("m7_ntt/pointwise_mul_inverse", |b| {
        b.iter(|| {
            (black_box(&ntt) * black_box(&rhs)).inverse_ntt();
        });
    });
}

fn bench_sampling(c: &mut Criterion) {
    let mut expand_a_group = c.benchmark_group("m7_sampling_expand_a");
    for parameter_set in PARAMETER_SETS {
        expand_a_group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandASeed::new(seed32(ps, 1));
                b.iter(|| expand_a(black_box(seed), ps).unwrap());
            },
        );
    }
    expand_a_group.finish();

    let mut expand_s_group = c.benchmark_group("m7_sampling_expand_s");
    for parameter_set in PARAMETER_SETS {
        expand_s_group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandSSeed::new(seed64(ps, 2));
                b.iter(|| expand_s(black_box(seed), ps).unwrap());
            },
        );
    }
    expand_s_group.finish();

    let mut expand_mask_group = c.benchmark_group("m7_sampling_expand_mask");
    for parameter_set in PARAMETER_SETS {
        expand_mask_group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = ExpandMaskSeed::new(seed64(ps, 3));
                b.iter(|| expand_mask(black_box(seed), black_box(13), ps).unwrap());
            },
        );
    }
    expand_mask_group.finish();

    let mut challenge_group = c.benchmark_group("m7_sampling_sample_in_ball");
    for parameter_set in PARAMETER_SETS {
        challenge_group.bench_with_input(
            BenchmarkId::from_parameter(parameter_set.name),
            &parameter_set,
            |b, &ps| {
                let seed = vec![ps.security_category.wrapping_add(4); ps.challenge_bytes()];
                b.iter(|| sample_in_ball(black_box(&seed), ps).unwrap());
            },
        );
    }
    challenge_group.finish();
}

fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_encoding_raw");

    for parameter_set in PARAMETER_SETS {
        let key_pair =
            KeyPair::generate_from_seed(parameter_set, seed32(parameter_set, 5)).unwrap();
        let message = format!("M7 encoding benchmark {}", parameter_set.name);
        let signature =
            sign_deterministic_for_test(key_pair.private_key(), message.as_bytes(), b"m7").unwrap();
        let public_parts = pk_decode(key_pair.public_key().as_bytes(), parameter_set).unwrap();
        let private_parts = sk_decode(key_pair.private_key().as_bytes(), parameter_set).unwrap();
        let signature_parts = sig_decode(signature.as_bytes(), parameter_set).unwrap();
        let w1 = PolyVector::zero_k(parameter_set);

        group.bench_function(format!("{}/pk_encode", parameter_set.name), |b| {
            b.iter(|| {
                pk_encode(
                    black_box(public_parts.rho),
                    black_box(&public_parts.t1),
                    parameter_set,
                )
                .unwrap();
            });
        });
        group.bench_function(format!("{}/pk_decode", parameter_set.name), |b| {
            b.iter(|| {
                pk_decode(black_box(key_pair.public_key().as_bytes()), parameter_set).unwrap();
            });
        });
        group.bench_function(format!("{}/sk_encode", parameter_set.name), |b| {
            b.iter(|| {
                sk_encode(
                    black_box(private_parts.rho),
                    black_box(private_parts.secret_key_seed),
                    black_box(private_parts.tr),
                    black_box(&private_parts.s1),
                    black_box(&private_parts.s2),
                    black_box(&private_parts.t0),
                    parameter_set,
                )
                .unwrap();
            });
        });
        group.bench_function(format!("{}/sk_decode", parameter_set.name), |b| {
            b.iter(|| {
                sk_decode(black_box(key_pair.private_key().as_bytes()), parameter_set).unwrap();
            });
        });
        group.bench_function(format!("{}/sig_encode", parameter_set.name), |b| {
            b.iter(|| {
                sig_encode(
                    black_box(&signature_parts.c_tilde),
                    black_box(&signature_parts.z),
                    black_box(&signature_parts.hints),
                    parameter_set,
                )
                .unwrap();
            });
        });
        group.bench_function(format!("{}/sig_decode", parameter_set.name), |b| {
            b.iter(|| {
                sig_decode(black_box(signature.as_bytes()), parameter_set).unwrap();
            });
        });
        group.bench_function(format!("{}/w1_encode", parameter_set.name), |b| {
            b.iter(|| {
                w1_encode(black_box(&w1), parameter_set).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_pkix_der(c: &mut Criterion) {
    let mut group = c.benchmark_group("m7_pkix_der");

    for parameter_set in PARAMETER_SETS {
        let seed = seed32(parameter_set, 6);
        let key_pair = KeyPair::generate_from_seed(parameter_set, seed).unwrap();
        let private_choice = PkixPrivateKey::Both {
            seed,
            expanded_key: key_pair.private_key().clone(),
        };
        let spki_der = subject_public_key_info_der(key_pair.public_key()).unwrap();
        let one_asymmetric_key_der =
            encode_one_asymmetric_key(parameter_set, &private_choice, Some(key_pair.public_key()))
                .unwrap();

        group.bench_function(format!("{}/spki_encode", parameter_set.name), |b| {
            b.iter(|| subject_public_key_info_der(black_box(key_pair.public_key())).unwrap());
        });
        group.bench_function(format!("{}/spki_decode", parameter_set.name), |b| {
            b.iter(|| decode_subject_public_key_info(black_box(&spki_der)).unwrap());
        });
        group.bench_function(
            format!("{}/one_asymmetric_key_encode", parameter_set.name),
            |b| {
                b.iter(|| {
                    encode_one_asymmetric_key(
                        parameter_set,
                        black_box(&private_choice),
                        Some(black_box(key_pair.public_key())),
                    )
                    .unwrap();
                });
            },
        );
        group.bench_function(
            format!("{}/one_asymmetric_key_decode", parameter_set.name),
            |b| {
                b.iter(|| parse_one_asymmetric_key(black_box(&one_asymmetric_key_der)).unwrap());
            },
        );
    }

    group.finish();
}

fn deterministic_poly(stream: u8) -> Poly {
    Poly::from_coeffs(core::array::from_fn(|index| {
        Coefficient::canonical((index as i64 * 37) + stream as i64)
    }))
}

fn seed32(parameter_set: ParameterSet, stream: u8) -> [u8; 32] {
    core::array::from_fn(|index| seed_byte(parameter_set, stream, index))
}

fn seed64(parameter_set: ParameterSet, stream: u8) -> [u8; 64] {
    core::array::from_fn(|index| seed_byte(parameter_set, stream, index))
}

fn seed_byte(parameter_set: ParameterSet, stream: u8, index: usize) -> u8 {
    parameter_set
        .security_category
        .wrapping_mul(41)
        .wrapping_add(stream)
        .wrapping_add(index as u8)
}

criterion_group! {
    name = benches;
    config = criterion();
    targets = bench_ntt, bench_sampling, bench_encoding, bench_pkix_der
}
criterion_main!(benches);

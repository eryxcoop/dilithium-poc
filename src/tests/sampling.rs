use super::*;

fn first_centered_values(poly: &Poly, count: usize) -> Vec<i32> {
    poly.iter()
        .take(count)
        .map(|coefficient| Coefficient::centered(coefficient.value() as i64).value())
        .collect()
}

#[test]
fn shake_vectors_match_known_outputs() {
    let shake128_hex = hex_string(&shake128(b"abc", 32));
    let shake256_hex = hex_string(&shake256(b"abc", 64));

    assert_eq!(
        shake128_hex,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
    );
    assert_eq!(
        shake256_hex,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
    );
}

#[test]
fn rej_ntt_poly_is_deterministic_for_fixed_seed() {
    let seed = RejNttPolySeed::new(core::array::from_fn(|index| index as u8));

    let first = rej_ntt_poly(seed).unwrap();
    let second = rej_ntt_poly(seed).unwrap();

    assert_eq!(first, second);
    assert!(first.iter().all(|coefficient| {
        let value = coefficient.value();
        (0..Q as i32).contains(&value)
    }));
}

#[test]
fn rej_bounded_poly_is_deterministic_and_bounded() {
    let seed = RejBoundedPolySeed::new(core::array::from_fn(|index| (255 - index) as u8));

    let first = rej_bounded_poly(seed, 2).unwrap();
    let second = rej_bounded_poly(seed, 2).unwrap();

    assert_eq!(first, second);
    assert!(
        first_centered_values(&first, N)
            .into_iter()
            .all(|value| (-2..=2).contains(&value))
    );
}

#[test]
fn rej_bounded_poly_rejects_unsupported_eta() {
    let error = rej_bounded_poly(RejBoundedPolySeed::new([0u8; 66]), 3).unwrap_err();

    assert_eq!(error, DilithiumError::InvalidParameterSet);
}

#[test]
fn rej_bounded_poly_report_counts_byte_loops_and_nibble_rejections() {
    let sampled = rej_bounded_poly_with_limits(
        RejBoundedPolySeed::new([1u8; 66]),
        4,
        SamplingLimits::default(),
    )
    .unwrap();
    let report = sampled.report();

    assert_eq!(report.xof_bytes(), report.loop_iterations());
    assert!(report.rejections() <= 2 * report.loop_iterations());
}

#[test]
fn expand_a_is_deterministic_and_shape_aware() {
    let seed = ExpandASeed::new([42u8; 32]);

    let first = expand_a(seed, ML_DSA_44).unwrap();
    let second = expand_a(seed, ML_DSA_44).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.shape(), (ML_DSA_44.core.k, ML_DSA_44.core.l));
    assert!(first.get(0, 0).is_some());
    assert!(first.get(ML_DSA_44.core.k, 0).is_none());
}

#[test]
fn expand_s_is_deterministic_and_matches_dimensions() {
    let seed = ExpandSSeed::new([99u8; 64]);

    let (s1_first, s2_first) = expand_s(seed, ML_DSA_65).unwrap();
    let (s1_second, s2_second) = expand_s(seed, ML_DSA_65).unwrap();

    assert_eq!(s1_first, s1_second);
    assert_eq!(s2_first, s2_second);
    assert_eq!(s1_first.dimension(), ML_DSA_65.core.l);
    assert_eq!(s2_first.dimension(), ML_DSA_65.core.k);

    for poly in s1_first.iter().chain(s2_first.iter()) {
        assert!(
            first_centered_values(poly, N)
                .into_iter()
                .all(|value| (-4..=4).contains(&value))
        );
    }
}

#[test]
fn expand_mask_is_deterministic_and_uses_gamma1_range() {
    let seed = ExpandMaskSeed::new([7u8; 64]);

    let first = expand_mask(seed, 17, ML_DSA_87).unwrap();
    let second = expand_mask(seed, 17, ML_DSA_87).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.dimension(), ML_DSA_87.core.l);

    let min = -(ML_DSA_87.core.gamma1 as i32) + 1;
    let max = ML_DSA_87.core.gamma1 as i32;
    for poly in first.iter() {
        assert!(
            first_centered_values(poly, N)
                .into_iter()
                .all(|value| (min..=max).contains(&value))
        );
    }
}

#[test]
fn sample_in_ball_is_deterministic_and_has_expected_weight() {
    let seed = vec![0xabu8; ML_DSA_44.challenge_bytes()];

    let first = sample_in_ball(&seed, ML_DSA_44).unwrap();
    let second = sample_in_ball(&seed, ML_DSA_44).unwrap();
    let values = first_centered_values(&first, N);

    assert_eq!(first, second);
    assert_eq!(
        values.iter().filter(|&&value| value != 0).count(),
        ML_DSA_44.core.tau as usize
    );
    assert!(values.into_iter().all(|value| (-1..=1).contains(&value)));
}

#[test]
fn sample_in_ball_rejects_wrong_challenge_seed_length() {
    let seed = vec![0xabu8; ML_DSA_44.challenge_bytes() - 1];

    let error = sample_in_ball(&seed, ML_DSA_44).unwrap_err();

    assert_eq!(
        error,
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.challenge_bytes(),
            actual: ML_DSA_44.challenge_bytes() - 1,
            item: "SampleInBall seed",
        }
    );
}

#[test]
fn sampling_limits_reject_values_below_fips_minima() {
    let limits = SamplingLimits::default().with_rej_ntt_poly(AlgorithmSamplingLimits::with_both(
        REJ_NTT_POLY_MIN_LOOP_LIMIT - 1,
        REJ_NTT_POLY_MIN_XOF_BYTES,
    ));

    let error = expand_a_with_limits(ExpandASeed::new([0u8; 32]), ML_DSA_44, limits).unwrap_err();
    assert_eq!(
        error,
        DilithiumError::LimitTooSmall {
            algorithm: "RejNTTPoly",
            limit_kind: "loop iterations",
            minimum: REJ_NTT_POLY_MIN_LOOP_LIMIT,
            actual: REJ_NTT_POLY_MIN_LOOP_LIMIT - 1,
        }
    );

    let bounded_limits =
        SamplingLimits::default().with_rej_bounded_poly(AlgorithmSamplingLimits::with_both(
            REJ_BOUNDED_POLY_MIN_LOOP_LIMIT,
            REJ_BOUNDED_POLY_MIN_XOF_BYTES - 1,
        ));

    assert!(rej_bounded_poly(RejBoundedPolySeed::new([0u8; 66]), 2).is_ok());

    let error = rej_bounded_poly_with_limits(RejBoundedPolySeed::new([0u8; 66]), 2, bounded_limits)
        .unwrap_err();
    assert_eq!(
        error,
        DilithiumError::LimitTooSmall {
            algorithm: "RejBoundedPoly",
            limit_kind: "xof bytes",
            minimum: REJ_BOUNDED_POLY_MIN_XOF_BYTES,
            actual: REJ_BOUNDED_POLY_MIN_XOF_BYTES - 1,
        }
    );

    let sample_limits =
        SamplingLimits::default().with_sample_in_ball(AlgorithmSamplingLimits::with_both(
            SAMPLE_IN_BALL_MIN_LOOP_LIMIT - 1,
            SAMPLE_IN_BALL_MIN_XOF_BYTES,
        ));
    let error = sample_in_ball_with_limits(&[0u8; 32], ML_DSA_44, sample_limits).unwrap_err();
    assert_eq!(
        error,
        DilithiumError::LimitTooSmall {
            algorithm: "SampleInBall",
            limit_kind: "loop iterations",
            minimum: SAMPLE_IN_BALL_MIN_LOOP_LIMIT,
            actual: SAMPLE_IN_BALL_MIN_LOOP_LIMIT - 1,
        }
    );
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

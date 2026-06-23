use super::*;

fn binary_hint_poly(indices: &[usize]) -> Poly {
    let mut coeffs = [Coefficient::default(); N];
    for &index in indices {
        coeffs[index] = Coefficient::from(1);
    }
    Poly::from_coeffs(coeffs)
}

#[test]
fn bits_to_integer_uses_little_endian_bit_order() {
    assert_eq!(bits_to_integer(&[1, 0, 1, 1]).unwrap(), 13);
    assert_eq!(bits_to_integer(&[0, 1, 0, 1, 1]).unwrap(), 26);
}

#[test]
fn integer_to_bytes_uses_little_endian_byte_order() {
    assert_eq!(
        integer_to_bytes(0x12_34_56, 4),
        vec![0x56, 0x34, 0x12, 0x00]
    );
    assert_eq!(integer_to_bytes(257, 2), vec![1, 1]);
}

#[test]
fn bits_and_bytes_roundtrip() {
    let bytes = vec![0xa5, 0x01, 0xfe];
    let bits = bytes_to_bits(&bytes);

    assert_eq!(bits_to_bytes(&bits).unwrap(), bytes);
}

#[test]
fn simple_bit_pack_and_unpack_roundtrip() {
    let mut values = [Coefficient::default(); N];
    values[0] = Coefficient::from(0);
    values[1] = Coefficient::from(3);
    values[2] = Coefficient::from(7);
    values[3] = Coefficient::from(1);
    values[4] = Coefficient::from(4);
    values[5] = Coefficient::from(2);
    let poly = Poly::from_coeffs(values);

    let packed = simple_bit_pack(&poly, 7).unwrap();
    let unpacked = simple_bit_unpack(&packed, 7).unwrap();

    assert_eq!(unpacked, Poly::from_coeffs(values));
}

#[test]
fn bit_pack_and_unpack_roundtrip() {
    let mut values = [Coefficient::default(); N];
    values[0] = Coefficient::from(0);
    values[1] = Coefficient::from((Q - 2) as i32);
    values[2] = Coefficient::from(2);
    values[3] = Coefficient::from((Q - 1) as i32);
    values[4] = Coefficient::from(1);
    values[5] = Coefficient::from(2);
    let poly = Poly::from_coeffs(values);

    let packed = bit_pack(&poly, 2, 2).unwrap();
    let unpacked = bit_unpack(&packed, 2, 2).unwrap();

    assert_eq!(unpacked, Poly::from_coeffs(values));
}

#[test]
fn bits_to_bytes_rejects_non_binary_input() {
    assert_eq!(
        bits_to_bytes(&[0, 1, 2]).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "bit",
            min: 0,
            max: 1,
            actual: 2,
        }
    );
}

#[test]
fn simple_bit_unpack_rejects_malformed_out_of_range_coefficients() {
    let malformed = vec![0x0f; 128];

    assert_eq!(
        simple_bit_unpack(&malformed, 10).unwrap_err(),
        DilithiumError::MalformedEncoding("simple bit unpack produced out-of-range coefficient")
    );
}

#[test]
fn bit_unpack_rejects_malformed_out_of_range_coefficients() {
    let malformed = vec![0x0f; 96];

    assert_eq!(
        bit_unpack(&malformed, 2, 2).unwrap_err(),
        DilithiumError::MalformedEncoding("bit unpack produced out-of-range coefficient")
    );
}

#[test]
fn unpack_rejects_wrong_lengths() {
    assert_eq!(
        simple_bit_unpack(&[], 7).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 96,
            actual: 0,
            item: "simple bit packed polynomial",
        }
    );
    assert_eq!(
        bit_unpack(&[], 2, 2).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: 96,
            actual: 0,
            item: "bit packed polynomial",
        }
    );
}

#[test]
fn hint_bit_pack_and_unpack_roundtrip() {
    let hints = HintsVector::new(
        ML_DSA_44,
        PolyVector::from_polys(
            ML_DSA_44.core.k,
            vec![
                binary_hint_poly(&[0, 7]),
                binary_hint_poly(&[3]),
                binary_hint_poly(&[]),
                binary_hint_poly(&[255]),
            ],
        )
        .unwrap(),
    )
    .unwrap();

    let packed = hint_bit_pack(&hints).unwrap();
    let unpacked = hint_bit_unpack(&packed, ML_DSA_44).unwrap();

    assert_eq!(
        packed.len(),
        ML_DSA_44.core.omega as usize + ML_DSA_44.core.k
    );
    assert_eq!(packed[0..4], [0, 7, 3, 255]);
    assert_eq!(packed[80..84], [2, 3, 3, 4]);
    assert_eq!(unpacked, hints);
}

#[test]
fn hints_vector_rejects_wrong_dimension() {
    let hints = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_44, hints).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.k,
            actual: 1,
            item: "hint vector dimension",
        }
    );
}

#[test]
fn hints_vector_rejects_non_binary_coefficients() {
    let hints = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            Poly::from_coeffs({
                let mut coeffs = [Coefficient::default(); N];
                coeffs[0] = Coefficient::from(2);
                coeffs
            }),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_44, hints).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "hint coefficient",
            min: 0,
            max: 1,
            actual: 2,
        }
    );
}

#[test]
fn hints_vector_rejects_weight_above_omega() {
    let hints = PolyVector::from_polys(
        ML_DSA_65.core.k,
        vec![
            binary_hint_poly(&(0..=ML_DSA_65.core.omega as usize).collect::<Vec<_>>()),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        HintsVector::new(ML_DSA_65, hints).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "hint weight",
            min: 0,
            max: ML_DSA_65.core.omega as i64,
            actual: ML_DSA_65.core.omega as i64 + 1,
        }
    );
}

#[test]
fn hint_bit_unpack_rejects_wrong_length() {
    assert_eq!(
        hint_bit_unpack(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.core.omega as usize + ML_DSA_44.core.k,
            actual: 0,
            item: "hint encoding",
        }
    );
}

#[test]
fn hint_bit_unpack_rejects_non_monotonic_boundaries() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 0;
    malformed[1] = 1;
    malformed[80] = 2;
    malformed[81] = 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint boundary is not monotonic or exceeds omega")
    );
}

#[test]
fn hint_bit_unpack_rejects_boundaries_above_omega() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[80] = ML_DSA_44.core.omega as u8 + 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint boundary is not monotonic or exceeds omega")
    );
}

#[test]
fn hint_bit_unpack_rejects_duplicate_or_descending_indices() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 7;
    malformed[1] = 7;
    malformed[80] = 2;
    malformed[81] = 2;
    malformed[82] = 2;
    malformed[83] = 2;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("hint indices are not strictly increasing")
    );
}

#[test]
fn hint_bit_unpack_rejects_nonzero_leftover_index_bytes() {
    let mut malformed = vec![0u8; ML_DSA_44.core.omega as usize + ML_DSA_44.core.k];
    malformed[0] = 1;

    assert_eq!(
        hint_bit_unpack(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("unused hint index byte is nonzero")
    );
}

#[test]
fn public_key_encode_and_decode_roundtrip() {
    let rho = [7u8; 32];
    let t1 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 0), (1, 1023)]),
            poly_with_coefficients(&[(2, 17)]),
            poly_with_coefficients(&[(3, 511)]),
            poly_with_coefficients(&[(4, 999)]),
        ],
    )
    .unwrap();

    let encoded = pk_encode(rho, &t1, ML_DSA_44).unwrap();
    let decoded = pk_decode(&encoded, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), ML_DSA_44.sizes.public_key_bytes);
    assert_eq!(decoded.rho, rho);
    assert_eq!(decoded.t1, t1);
}

#[test]
fn public_key_encode_rejects_wrong_t1_dimension() {
    let t1 = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();

    assert_eq!(
        pk_encode([0u8; 32], &t1, ML_DSA_44).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.k,
            actual: 1,
            item: "public key t1 vector",
        }
    );
}

#[test]
fn public_key_encode_rejects_out_of_range_t1_coefficients() {
    let t1 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 1024)]),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        pk_encode([0u8; 32], &t1, ML_DSA_44).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "packed coefficient",
            min: 0,
            max: 1023,
            actual: 1024,
        }
    );
}

#[test]
fn public_key_decode_rejects_wrong_length() {
    assert_eq!(
        pk_decode(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.sizes.public_key_bytes,
            actual: 0,
            item: "public key",
        }
    );
}

#[test]
fn private_key_encode_and_decode_roundtrip() {
    let rho = [1u8; 32];
    let secret_key_seed = [2u8; 32];
    let tr = [3u8; 64];
    let s1 = PolyVector::from_polys(
        ML_DSA_44.core.l,
        vec![
            poly_with_coefficients(&[(0, -2), (1, 2)]),
            poly_with_coefficients(&[(2, -1)]),
            poly_with_coefficients(&[(3, 1)]),
            Poly::zero(),
        ],
    )
    .unwrap();
    let s2 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(4, 2)]),
            poly_with_coefficients(&[(5, -2)]),
            Poly::zero(),
            poly_with_coefficients(&[(6, 1)]),
        ],
    )
    .unwrap();
    let t0 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, -4095), (1, 4096)]),
            poly_with_coefficients(&[(2, -1)]),
            poly_with_coefficients(&[(3, 1)]),
            Poly::zero(),
        ],
    )
    .unwrap();

    let encoded = sk_encode(rho, secret_key_seed, tr, &s1, &s2, &t0, ML_DSA_44).unwrap();
    let decoded = sk_decode(&encoded, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), ML_DSA_44.sizes.private_key_bytes);
    assert_eq!(decoded.rho, rho);
    assert_eq!(decoded.secret_key_seed, secret_key_seed);
    assert_eq!(decoded.tr, tr);
    assert_eq!(decoded.s1, s1);
    assert_eq!(decoded.s2, s2);
    assert_eq!(decoded.t0, t0);
}

#[test]
fn private_key_encode_rejects_wrong_dimensions() {
    let wrong_s1 = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();
    let s2 = PolyVector::zero_k(ML_DSA_44);
    let t0 = PolyVector::zero_k(ML_DSA_44);

    assert_eq!(
        sk_encode(
            [0u8; 32], [0u8; 32], [0u8; 64], &wrong_s1, &s2, &t0, ML_DSA_44,
        )
        .unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.l,
            actual: 1,
            item: "private key s1 vector",
        }
    );
}

#[test]
fn private_key_decode_rejects_wrong_length() {
    assert_eq!(
        sk_decode(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.sizes.private_key_bytes,
            actual: 0,
            item: "private key",
        }
    );
}

#[test]
fn private_key_decode_rejects_malformed_secret_polynomial() {
    let s1 = PolyVector::zero_l(ML_DSA_44);
    let s2 = PolyVector::zero_k(ML_DSA_44);
    let t0 = PolyVector::zero_k(ML_DSA_44);
    let mut encoded = sk_encode([0u8; 32], [0u8; 32], [0u8; 64], &s1, &s2, &t0, ML_DSA_44).unwrap();

    encoded[128] = 0b0000_0111;

    assert_eq!(
        sk_decode(&encoded, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("bit unpack produced out-of-range coefficient")
    );
}

#[test]
fn w1_encode_matches_expected_size_and_rejects_out_of_range_coefficients() {
    let w1 = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 0), (1, 43)]),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    let encoded = w1_encode(&w1, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), 768);

    let malformed = PolyVector::from_polys(
        ML_DSA_44.core.k,
        vec![
            poly_with_coefficients(&[(0, 44)]),
            Poly::zero(),
            Poly::zero(),
            Poly::zero(),
        ],
    )
    .unwrap();

    assert_eq!(
        w1_encode(&malformed, ML_DSA_44).unwrap_err(),
        DilithiumError::ValueOutOfRange {
            item: "packed coefficient",
            min: 0,
            max: 43,
            actual: 44,
        }
    );
}

#[test]
fn signature_encode_and_decode_roundtrip() {
    let c_tilde = vec![0x5au8; ML_DSA_44.core.lambda as usize / 4];
    let z = PolyVector::from_polys(
        ML_DSA_44.core.l,
        vec![
            poly_with_coefficients(&[(0, -(ML_DSA_44.core.gamma1 as i32) + 1)]),
            poly_with_coefficients(&[(1, ML_DSA_44.core.gamma1 as i32)]),
            Poly::zero(),
            poly_with_coefficients(&[(2, 17)]),
        ],
    )
    .unwrap();
    let hints = HintsVector::new(
        ML_DSA_44,
        PolyVector::from_polys(
            ML_DSA_44.core.k,
            vec![
                binary_hint_poly(&[0, 7]),
                binary_hint_poly(&[3]),
                binary_hint_poly(&[]),
                binary_hint_poly(&[255]),
            ],
        )
        .unwrap(),
    )
    .unwrap();

    let encoded = sig_encode(&c_tilde, &z, &hints, ML_DSA_44).unwrap();
    let decoded = sig_decode(&encoded, ML_DSA_44).unwrap();

    assert_eq!(encoded.len(), ML_DSA_44.sizes.signature_bytes);
    assert_eq!(decoded.c_tilde, c_tilde);
    assert_eq!(decoded.z, z);
    assert_eq!(decoded.hints, hints);
}

#[test]
fn signature_encode_rejects_wrong_challenge_length() {
    let z = PolyVector::zero_l(ML_DSA_44);
    let hints = HintsVector::new(ML_DSA_44, PolyVector::zero_k(ML_DSA_44)).unwrap();

    assert_eq!(
        sig_encode(&[], &z, &hints, ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.core.lambda as usize / 4,
            actual: 0,
            item: "signature challenge",
        }
    );
}

#[test]
fn signature_encode_rejects_wrong_z_dimension() {
    let c_tilde = vec![0u8; ML_DSA_44.core.lambda as usize / 4];
    let z = PolyVector::from_polys(1, vec![Poly::zero()]).unwrap();
    let hints = HintsVector::new(ML_DSA_44, PolyVector::zero_k(ML_DSA_44)).unwrap();

    assert_eq!(
        sig_encode(&c_tilde, &z, &hints, ML_DSA_44).unwrap_err(),
        DilithiumError::DimensionMismatch {
            expected: ML_DSA_44.core.l,
            actual: 1,
            item: "signature z vector",
        }
    );
}

#[test]
fn signature_decode_rejects_wrong_length() {
    assert_eq!(
        sig_decode(&[], ML_DSA_44).unwrap_err(),
        DilithiumError::InvalidLength {
            expected: ML_DSA_44.sizes.signature_bytes,
            actual: 0,
            item: "signature",
        }
    );
}

#[test]
fn signature_decode_rejects_malformed_hints() {
    let c_tilde = vec![0u8; ML_DSA_44.core.lambda as usize / 4];
    let z = PolyVector::zero_l(ML_DSA_44);
    let hints = HintsVector::new(ML_DSA_44, PolyVector::zero_k(ML_DSA_44)).unwrap();
    let mut encoded = sig_encode(&c_tilde, &z, &hints, ML_DSA_44).unwrap();
    let hint_offset = encoded.len() - (ML_DSA_44.core.omega as usize + ML_DSA_44.core.k);
    encoded[hint_offset] = 1;

    assert_eq!(
        sig_decode(&encoded, ML_DSA_44).unwrap_err(),
        DilithiumError::MalformedEncoding("unused hint index byte is nonzero")
    );
}

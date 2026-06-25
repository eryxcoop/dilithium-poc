use crate::coefficient::{CANONICAL_MAX, CANONICAL_MIN, CENTERED_MAX, CENTERED_MIN, Coefficient};
use crate::encoding::{
    bit_pack, bit_unpack, bits_to_bytes, bits_to_integer, bytes_to_bits, hint_bit_pack,
    hint_bit_unpack, integer_to_bytes, pk_decode, pk_encode, sig_decode, sig_encode,
    simple_bit_pack, simple_bit_unpack, sk_decode, sk_encode, w1_encode,
};
use crate::error::DilithiumError;
use crate::hints::HintsVector;
use crate::ml_dsa::{PublicKey, Signature, verify_lengths};
use crate::params::{
    CoreParams, D, EncodedSizes, ML_DSA_44, ML_DSA_65, ML_DSA_87, N, PARAMETER_SETS, ParameterSet,
    ParameterSetId, Q, ZETA,
};
use crate::poly::{NttPoly, NttPolyVector, Poly, PolyMatrix, PolyVector};
use crate::sampling::{
    AlgorithmSamplingLimits, ExpandASeed, ExpandMaskSeed, ExpandSSeed,
    REJ_BOUNDED_POLY_MIN_LOOP_LIMIT, REJ_BOUNDED_POLY_MIN_XOF_BYTES, REJ_NTT_POLY_MIN_LOOP_LIMIT,
    REJ_NTT_POLY_MIN_XOF_BYTES, RejBoundedPolySeed, RejNttPolySeed, SAMPLE_IN_BALL_MIN_LOOP_LIMIT,
    SAMPLE_IN_BALL_MIN_XOF_BYTES, SamplingLimits, expand_a, expand_a_with_limits, expand_mask,
    expand_s, rej_bounded_poly, rej_bounded_poly_with_limits, rej_ntt_poly, sample_in_ball,
    sample_in_ball_with_limits,
};
use crate::xof::{shake128, shake256};

mod algebra;
mod encoding;
mod ml_dsa;
mod ntt;
mod params;
mod rounding;
mod sampling;
mod verify;

fn poly_with_coefficients(entries: &[(usize, i32)]) -> Poly {
    let mut coeffs = [Coefficient::default(); N];
    for &(index, value) in entries {
        coeffs[index] = Coefficient::from(value);
    }
    Poly::from_coeffs(coeffs)
}

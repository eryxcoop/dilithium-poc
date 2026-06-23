use crate::coefficient::{CANONICAL_MAX, CANONICAL_MIN, CENTERED_MAX, CENTERED_MIN, Coefficient};
use crate::encoding::{
    bit_pack, bit_unpack, bits_to_bytes, bits_to_integer, bytes_to_bits, hint_bit_pack,
    hint_bit_unpack, integer_to_bytes, pk_decode, pk_encode, sig_decode, sig_encode,
    simple_bit_pack, simple_bit_unpack, sk_decode, sk_encode, w1_encode,
};
use crate::error::DilithiumError;
use crate::hints::HintsVector;
use crate::params::{
    CoreParams, D, EncodedSizes, ML_DSA_44, ML_DSA_65, ML_DSA_87, N, PARAMETER_SETS, ParameterSet,
    ParameterSetId, Q, ZETA,
};
use crate::poly::{NttPoly, Poly, PolyMatrix, PolyVector};
use crate::verify::verify_lengths;

mod algebra;
mod encoding;
mod ntt;
mod params;
mod rounding;
mod verify;

fn poly_with_coefficients(entries: &[(usize, i32)]) -> Poly {
    let mut coeffs = [Coefficient::default(); N];
    for &(index, value) in entries {
        coeffs[index] = Coefficient::from(value);
    }
    Poly::from_coeffs(coeffs)
}

//! Signature encoders from FIPS 204 Section 7.2.
//!
//! This module implements `sigEncode`, `sigDecode`, and `w1Encode`. These are
//! raw FIPS 204 byte-string encoders, not ASN.1 or PKIX wrappers.

use crate::encoding::shared::{bit_length, packed_poly_bytes};
use crate::encoding::{bit_pack, bit_unpack, hint_bit_pack, hint_bit_unpack, simple_bit_pack};
use crate::error::DilithiumResult;
use crate::hints::HintsVector;
use crate::params::ParameterSet;
use crate::poly::PolyVector;
use crate::validation::{ensure_dimension, ensure_len};

/// Decoded components of a raw FIPS 204 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSignatureParts {
    /// Signer's commitment hash `c̃` with length `λ/4`.
    pub c_tilde: Vec<u8>,
    /// Response vector `z` with dimension `l`.
    pub z: PolyVector,
    /// Sparse hint vector `h` with dimension `k` and weight at most `omega`.
    pub hints: HintsVector,
}

/// Encodes the high bits `w1` using FIPS 204 `w1Encode`.
///
/// The vector must have dimension `k`, and every coefficient must lie in
/// `[0, (q - 1) / (2 * γ_2) - 1]`.
pub fn w1_encode(w1: &PolyVector, parameter_set: ParameterSet) -> DilithiumResult<Vec<u8>> {
    ensure_dimension("w1 vector", parameter_set.core.k, w1.dimension())?;

    let max_value = parameter_set.w1_max();
    let mut encoding = Vec::with_capacity(
        parameter_set.core.k * packed_poly_bytes(bit_length(parameter_set.w1_max())),
    );

    for poly in w1.iter() {
        encoding.extend(simple_bit_pack(poly, max_value)?);
    }

    Ok(encoding)
}

/// Encodes a raw signature using FIPS 204 `sigEncode`.
///
/// `c̃` must have length `λ/4`, `z` must have dimension `l`, and
/// `hints` must belong to the same parameter set.
pub fn sig_encode(
    c_tilde: &[u8],
    z: &PolyVector,
    hints: &HintsVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<Vec<u8>> {
    ensure_len(
        "signature challenge",
        parameter_set.challenge_bytes(),
        c_tilde.len(),
    )?;
    ensure_dimension("signature z vector", parameter_set.core.l, z.dimension())?;
    hints.ensure_parameter_set(parameter_set)?;

    let mut signature = Vec::with_capacity(parameter_set.sizes.signature_bytes);
    signature.extend_from_slice(c_tilde);

    for poly in z.iter() {
        signature.extend(bit_pack(
            poly,
            parameter_set.core.gamma1 - 1,
            parameter_set.core.gamma1,
        )?);
    }

    signature.extend(hint_bit_pack(hints)?);
    Ok(signature)
}

/// Decodes a raw signature using FIPS 204 `sigDecode`.
///
/// This function rejects inputs whose length is not exactly
/// `parameter_set.sizes.signature_bytes`, malformed `z` polynomial encodings,
/// and malformed hint encodings.
pub fn sig_decode(
    signature: &[u8],
    parameter_set: ParameterSet,
) -> DilithiumResult<EncodedSignatureParts> {
    ensure_len(
        "signature",
        parameter_set.sizes.signature_bytes,
        signature.len(),
    )?;

    let challenge_len = parameter_set.challenge_bytes();
    let c_tilde = signature[..challenge_len].to_vec();
    let z_poly_bytes = packed_poly_bytes(1 + bit_length(parameter_set.core.gamma1 - 1));
    let mut offset = challenge_len;
    let mut z = Vec::with_capacity(parameter_set.core.l);

    for _ in 0..parameter_set.core.l {
        let end = offset + z_poly_bytes;
        z.push(bit_unpack(
            &signature[offset..end],
            parameter_set.core.gamma1 - 1,
            parameter_set.core.gamma1,
        )?);
        offset = end;
    }

    let hints = hint_bit_unpack(&signature[offset..], parameter_set)?;

    Ok(EncodedSignatureParts {
        c_tilde,
        z: PolyVector::from_polys(parameter_set.core.l, z)?,
        hints,
    })
}

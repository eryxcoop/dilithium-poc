//! FIPS 204 public-key encoder and decoder.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::poly::PolyVector;

use crate::encoding::{simple_bit_pack, simple_bit_unpack};

use super::shared::{
    array_from_slice, ensure_dimension, ensure_len, packed_poly_bytes, public_t1_bit_width,
    public_t1_max,
};
use super::types::{EncodedPublicKeyParts, RHO_BYTES, Rho};

/// Encodes a public key using FIPS 204 `pkEncode`.
///
/// The `t1` vector must have dimension `parameter_set.core.k`; each coefficient
/// must be in `[0, 2^(bitlen(q - 1) - d) - 1]`.
pub fn pk_encode(
    rho: Rho,
    t1: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<Vec<u8>> {
    ensure_dimension("public key t1 vector", parameter_set.core.k, t1.dimension())?;

    let mut public_key = Vec::with_capacity(parameter_set.sizes.public_key_bytes);
    public_key.extend_from_slice(&rho);

    for poly in t1.iter() {
        public_key.extend(simple_bit_pack(poly, public_t1_max())?);
    }

    Ok(public_key)
}

/// Decodes a public key using FIPS 204 `pkDecode`.
///
/// This function rejects inputs whose length is not exactly
/// `parameter_set.sizes.public_key_bytes` and rejects malformed `t1`
/// polynomial encodings.
pub fn pk_decode(
    public_key: &[u8],
    parameter_set: ParameterSet,
) -> DilithiumResult<EncodedPublicKeyParts> {
    ensure_len(
        "public key",
        parameter_set.sizes.public_key_bytes,
        public_key.len(),
    )?;

    let rho = array_from_slice::<RHO_BYTES>(&public_key[..RHO_BYTES]);
    let t1_poly_bytes = packed_poly_bytes(public_t1_bit_width());
    let mut offset = RHO_BYTES;
    let mut t1 = Vec::with_capacity(parameter_set.core.k);

    for _ in 0..parameter_set.core.k {
        let end = offset + t1_poly_bytes;
        t1.push(simple_bit_unpack(
            &public_key[offset..end],
            public_t1_max(),
        )?);
        offset = end;
    }

    Ok(EncodedPublicKeyParts {
        rho,
        t1: PolyVector::from_polys(parameter_set.core.k, t1)?,
    })
}

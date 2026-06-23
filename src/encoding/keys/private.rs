//! FIPS 204 expanded private-key encoder and decoder.

use crate::encoding::bit_pack;
use crate::error::DilithiumResult;
use crate::params::{D, ParameterSet};
use crate::poly::PolyVector;

use super::shared::{
    array_from_slice, bit_length, ensure_dimension, ensure_len, packed_poly_bytes, private_t0_a,
    private_t0_b, unpack_vector,
};
use super::types::{
    EncodedPrivateKeyParts, PublicKeyHash, RHO_BYTES, Rho, SECRET_KEY_SEED_BYTES, SecretKeySeed,
    TR_BYTES,
};

/// Encodes an expanded private key using FIPS 204 `skEncode`.
///
/// The `s1` vector must have dimension `l`; `s2` and `t0` must have dimension
/// `k`. Coefficient ranges are enforced by the underlying `BitPack` calls.
pub fn sk_encode(
    rho: Rho,
    secret_key_seed: SecretKeySeed,
    tr: PublicKeyHash,
    s1: &PolyVector,
    s2: &PolyVector,
    t0: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<Vec<u8>> {
    ensure_dimension(
        "private key s1 vector",
        parameter_set.core.l,
        s1.dimension(),
    )?;
    ensure_dimension(
        "private key s2 vector",
        parameter_set.core.k,
        s2.dimension(),
    )?;
    ensure_dimension(
        "private key t0 vector",
        parameter_set.core.k,
        t0.dimension(),
    )?;

    let mut private_key = Vec::with_capacity(parameter_set.sizes.private_key_bytes);
    private_key.extend_from_slice(&rho);
    private_key.extend_from_slice(&secret_key_seed);
    private_key.extend_from_slice(&tr);

    for poly in s1.iter() {
        private_key.extend(bit_pack(
            poly,
            parameter_set.core.eta,
            parameter_set.core.eta,
        )?);
    }

    for poly in s2.iter() {
        private_key.extend(bit_pack(
            poly,
            parameter_set.core.eta,
            parameter_set.core.eta,
        )?);
    }

    for poly in t0.iter() {
        private_key.extend(bit_pack(poly, private_t0_a(), private_t0_b())?);
    }

    Ok(private_key)
}

/// Decodes an expanded private key using FIPS 204 `skDecode`.
///
/// FIPS 204 treats `skDecode` as an internal routine for trusted inputs. This
/// POC still rejects malformed packed polynomials so downstream code receives
/// values in the documented ranges.
pub fn sk_decode(
    private_key: &[u8],
    parameter_set: ParameterSet,
) -> DilithiumResult<EncodedPrivateKeyParts> {
    ensure_len(
        "private key",
        parameter_set.sizes.private_key_bytes,
        private_key.len(),
    )?;

    let rho = array_from_slice::<RHO_BYTES>(&private_key[..RHO_BYTES]);
    let mut offset = RHO_BYTES;
    let secret_key_seed = array_from_slice::<SECRET_KEY_SEED_BYTES>(
        &private_key[offset..offset + SECRET_KEY_SEED_BYTES],
    );
    offset += SECRET_KEY_SEED_BYTES;
    let tr = array_from_slice::<TR_BYTES>(&private_key[offset..offset + TR_BYTES]);
    offset += TR_BYTES;

    let secret_poly_bytes = packed_poly_bytes(bit_length(2 * parameter_set.core.eta));
    let t0_poly_bytes = packed_poly_bytes(D as usize);

    let s1 = unpack_vector(
        private_key,
        &mut offset,
        parameter_set.core.l,
        secret_poly_bytes,
        parameter_set.core.eta,
        parameter_set.core.eta,
    )?;
    let s2 = unpack_vector(
        private_key,
        &mut offset,
        parameter_set.core.k,
        secret_poly_bytes,
        parameter_set.core.eta,
        parameter_set.core.eta,
    )?;
    let t0 = unpack_vector(
        private_key,
        &mut offset,
        parameter_set.core.k,
        t0_poly_bytes,
        private_t0_a(),
        private_t0_b(),
    )?;

    Ok(EncodedPrivateKeyParts {
        rho,
        secret_key_seed,
        tr,
        s1,
        s2,
        t0,
    })
}

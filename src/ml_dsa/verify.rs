//! FIPS 204 ML-DSA verification.

use crate::encoding::{pk_decode, sig_decode};
use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::sampling::{ExpandASeed, expand_a, sample_in_ball};

use super::context::format_message;
use super::keygen::public_key_hash;
use super::sign::{commitment_hash, message_representative};
use super::types::{PublicKey, Signature};

/// Verifies an ML-DSA signature for a byte-aligned message and context.
///
/// The `context` argument is the FIPS 204 pure ML-DSA context string. It must
/// match the context used during signing; a valid signature for one context
/// does not verify under a different context. Pass `b""` for the default
/// context, including RFC 9881 PKIX uses.
///
/// This is the external FIPS 204 `ML-DSA.Verify` path for pure ML-DSA. It
/// returns an error only for API-level failures such as a context longer than
/// 255 bytes. Malformed public keys, malformed signatures, parameter-set
/// mismatches, and cryptographic mismatches are reported as `Ok(false)`.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> DilithiumResult<bool> {
    let parameter_set = public_key.parameter_set();
    let formatted_message = format_message(message, context)?;

    if signature.parameter_set() != parameter_set {
        return Ok(false);
    }

    let public_parts = match pk_decode(public_key.as_bytes(), parameter_set) {
        Ok(parts) => parts,
        Err(_) => return Ok(false),
    };
    let signature_parts = match sig_decode(signature.as_bytes(), parameter_set) {
        Ok(parts) => parts,
        Err(_) => return Ok(false),
    };

    let a_hat = match expand_a(ExpandASeed::new(public_parts.rho), parameter_set) {
        Ok(a_hat) => a_hat,
        Err(_) => return Ok(false),
    };
    let tr = public_key_hash(public_key.as_bytes());
    let mu = message_representative(&tr, &formatted_message);
    let c = match sample_in_ball(&signature_parts.c_tilde, parameter_set) {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };

    let z_hat = signature_parts.z.ntt()?;
    let a_z = match a_hat.multiply_ntt_vector(&z_hat, parameter_set) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let c_hat = c.ntt();
    let t1_times_2d = match public_parts.t1.multiply_by_2_power_d() {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let t1_hat = t1_times_2d.ntt()?;
    let c_t1 = match c_hat.multiply_ntt_vector(&t1_hat, parameter_set.core.k) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let w_approx = match a_z.checked_sub(&c_t1) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let w1_prime = match signature_parts.hints.use_on(&w_approx) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let c_tilde_prime = match commitment_hash(&mu, &w1_prime, parameter_set) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };

    Ok(!signature_parts
        .z
        .infinity_norm_at_least(parameter_set.core.gamma1 - parameter_set.core.beta)
        && c_tilde_prime == signature_parts.c_tilde)
}

/// Returns `false` unless `public_key` and `signature` have exact FIPS 204 sizes.
///
/// A return value of `true` only means the byte strings have the correct size;
/// it does not mean the signature is cryptographically valid. Use [`verify`]
/// for full FIPS 204 verification.
pub fn verify_lengths(public_key: &[u8], signature: &[u8], parameter_set: ParameterSet) -> bool {
    public_key.len() == parameter_set.sizes.public_key_bytes
        && signature.len() == parameter_set.sizes.signature_bytes
}

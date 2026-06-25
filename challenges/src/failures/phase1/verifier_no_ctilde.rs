//! `verifier_no_ctilde`: skipping the challenge binding permits chosen-message forgery.

use dilithium_poc::coefficient::Coefficient;
use dilithium_poc::encoding::{pk_decode, sig_decode, sig_encode, w1_encode};
use dilithium_poc::error::DilithiumResult;
use dilithium_poc::hints::HintsVector;
use dilithium_poc::ml_dsa::{KeyPair, PublicKey, Signature};
use dilithium_poc::params::{D, ML_DSA_44, ParameterSet};
use dilithium_poc::poly::{NttMatrix, NttPoly, NttPolyVector, Poly, PolyVector};
use dilithium_poc::sampling::{ExpandASeed, expand_a, sample_in_ball};
use dilithium_poc::xof::shake256;

use crate::shared::{ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript};

/// Runs the missing-`c̃`-check classroom demo.
pub fn run() -> ChallengeRun {
    let key_pair = KeyPair::generate_from_seed(ML_DSA_44, [0x44; 32])
        .expect("fixed seed should generate an ML-DSA key pair");
    let message = b"forged message";
    let context = b"phase1";
    let forged_signature = forge_for_target_message(key_pair.public_key(), message, context);
    let replay_message = b"different forged message";
    let strict_accepts = key_pair
        .public_key()
        .verify(message, &forged_signature, context);
    let vulnerable_accepts =
        broken_verify_no_ctilde(key_pair.public_key(), message, &forged_signature, context);
    let replay_accepts = broken_verify_no_ctilde(
        key_pair.public_key(),
        replay_message,
        &forged_signature,
        context,
    );
    let strict_replay_accepts =
        key_pair
            .public_key()
            .verify(replay_message, &forged_signature, context);
    let success = vulnerable_accepts && replay_accepts && !strict_accepts && !strict_replay_accepts;

    let transcript = Transcript::new()
        .step(
            "Target",
            format!(
                "The attacker gets only the public key, the target message {:?}, and ctx {:?}.",
                String::from_utf8_lossy(message),
                String::from_utf8_lossy(context)
            ),
        )
        .step(
            "Forgery",
            format!(
                "The attacker builds a structurally valid ML-DSA-44 Signature with nonzero bounded z, h = 0, and target-derived c̃ = {:02x?}...",
                &forged_signature.as_bytes()[..4]
            ),
        )
        .step(
            "Vulnerable verifier",
            format!(
                "The broken verify() decodes pk and sig, computes μ, samples c, reconstructs w₁′, checks z and ω, but skips c̃ == H(μ || w1Encode(w₁′)); vulnerable_accepts = {vulnerable_accepts}."
            ),
        )
        .step(
            "Message replay",
            format!(
                "The same forged signature also passes the broken verifier for {:?}: replay_accepts = {replay_accepts}, while strict_replay_accepts = {strict_replay_accepts}.",
                String::from_utf8_lossy(replay_message)
            ),
        )
        .step(
            "Strict comparison",
            format!(
                "The real PublicKey::verify recomputes c̃′ from μ and w₁′, so strict_accepts = {strict_accepts}."
            ),
        )
        .step(
            "FIPS defense",
            "The final c̃ comparison binds the Fiat-Shamir challenge to μ and w₁′.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "verifier_no_ctilde",
            "Verifier Without c̃ Binding",
            ChallengeMode::RealParams,
            "skips c̃ == H(μ || w1Encode(w₁′))",
        ),
        transcript,
        success,
    )
}

fn forge_for_target_message(public_key: &PublicKey, message: &[u8], context: &[u8]) -> Signature {
    let c_tilde = target_derived_ctilde(public_key, message, context);
    let z = nonzero_bounded_z(ML_DSA_44);
    let hints = HintsVector::new(ML_DSA_44, PolyVector::zero_k(ML_DSA_44))
        .expect("zero hints satisfy omega");
    let encoded = sig_encode(&c_tilde, &z, &hints, ML_DSA_44)
        .expect("structural signature encoding should succeed");
    Signature::from_raw(ML_DSA_44, encoded).expect("encoded signature has exact FIPS length")
}

fn broken_verify_no_ctilde(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> bool {
    let parameter_set = public_key.parameter_set();

    if context.len() > 255 || signature.parameter_set() != parameter_set {
        return false;
    }

    let public_parts = match pk_decode(public_key.as_bytes(), parameter_set) {
        Ok(parts) => parts,
        Err(_) => return false,
    };
    let signature_parts = match sig_decode(signature.as_bytes(), parameter_set) {
        Ok(parts) => parts,
        Err(_) => return false,
    };

    let a_hat = match expand_a(ExpandASeed::new(public_parts.rho), parameter_set) {
        Ok(a_hat) => a_hat,
        Err(_) => return false,
    };
    let c = match sample_in_ball(&signature_parts.c_tilde, parameter_set) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let formatted_message = format_message(message, context);
    let tr = public_key_hash(public_key);
    let mu = message_representative(&tr, &formatted_message);
    let w_approx = match reconstruct_w_approx(
        &a_hat,
        &signature_parts.z,
        &c,
        &public_parts.t1,
        parameter_set,
    ) {
        Ok(w_approx) => w_approx,
        Err(_) => return false,
    };
    let w1_prime = match signature_parts.hints.use_on(&w_approx) {
        Ok(w1_prime) => w1_prime,
        Err(_) => return false,
    };
    let _c_tilde_prime = match challenge_seed(&mu, &w1_prime, parameter_set) {
        Ok(c_tilde_prime) => c_tilde_prime,
        Err(_) => return false,
    };

    let bound = parameter_set.core.gamma1 - parameter_set.core.beta;
    z_is_within_signing_bound(&signature_parts.z, bound)
        && signature_parts.hints.weight() <= parameter_set.core.omega as usize
}

#[cfg(test)]
fn forged_signature_with_z_at_bound() -> Signature {
    let c_tilde = vec![0xa5; ML_DSA_44.challenge_bytes()];
    let z = z_with_first_coefficient(ML_DSA_44, ML_DSA_44.core.gamma1 - ML_DSA_44.core.beta);
    let hints = HintsVector::new(ML_DSA_44, PolyVector::zero_k(ML_DSA_44))
        .expect("zero hints satisfy omega");
    let encoded = sig_encode(&c_tilde, &z, &hints, ML_DSA_44)
        .expect("out-of-bound z still has a structurally encodable value");
    Signature::from_raw(ML_DSA_44, encoded).expect("encoded signature has exact FIPS length")
}

fn z_is_within_signing_bound(z: &PolyVector, bound: u32) -> bool {
    z.iter().all(|poly| {
        poly.iter().all(|coefficient| {
            let centered = Coefficient::centered(coefficient.value() as i64).value();
            centered.unsigned_abs() < bound
        })
    })
}

fn nonzero_bounded_z(parameter_set: ParameterSet) -> PolyVector {
    z_with_first_coefficient(parameter_set, 1)
}

fn z_with_first_coefficient(parameter_set: ParameterSet, coefficient: u32) -> PolyVector {
    let mut polys = vec![Poly::zero(); parameter_set.core.l];
    let mut coeffs = [Coefficient::default(); dilithium_poc::params::N];
    coeffs[0] = Coefficient::from(coefficient as i32);
    polys[0] = Poly::from_coeffs(coeffs);
    PolyVector::from_polys(parameter_set.core.l, polys).expect("dimension matches l")
}

fn target_derived_ctilde(public_key: &PublicKey, message: &[u8], context: &[u8]) -> Vec<u8> {
    let formatted_message = format_message(message, context);
    let mut input = Vec::with_capacity(
        public_key.as_bytes().len() + formatted_message.len() + "verifier_no_ctilde".len(),
    );
    input.extend_from_slice(public_key.as_bytes());
    input.extend_from_slice(&formatted_message);
    input.extend_from_slice(b"verifier_no_ctilde");
    shake256(&input, public_key.parameter_set().challenge_bytes())
}

fn format_message(message: &[u8], context: &[u8]) -> Vec<u8> {
    let mut formatted = Vec::with_capacity(2 + context.len() + message.len());
    formatted.push(0);
    formatted.push(context.len() as u8);
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(message);
    formatted
}

fn public_key_hash(public_key: &PublicKey) -> [u8; 64] {
    let digest = shake256(public_key.as_bytes(), 64);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&digest);
    tr
}

fn message_representative(tr: &[u8; 64], formatted_message: &[u8]) -> [u8; 64] {
    let mut input = Vec::with_capacity(tr.len() + formatted_message.len());
    input.extend_from_slice(tr);
    input.extend_from_slice(formatted_message);

    let digest = shake256(&input, 64);
    let mut mu = [0u8; 64];
    mu.copy_from_slice(&digest);
    mu
}

fn challenge_seed(
    mu: &[u8; 64],
    w1_prime: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<Vec<u8>> {
    let encoded_w1 = w1_encode(w1_prime, parameter_set)?;
    let mut input = Vec::with_capacity(mu.len() + encoded_w1.len());
    input.extend_from_slice(mu);
    input.extend_from_slice(&encoded_w1);
    Ok(shake256(&input, parameter_set.challenge_bytes()))
}

fn reconstruct_w_approx(
    a_hat: &NttMatrix,
    z: &PolyVector,
    c: &Poly,
    t1: &PolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    let z_hat = ntt_vector(z)?;
    let a_z = multiply_matrix_by_ntt_vector(a_hat, &z_hat, parameter_set)?;
    let c_hat = c.ntt();
    let t1_times_2d = multiply_by_2_power_d(t1)?;
    let t1_hat = ntt_vector(&t1_times_2d)?;
    let c_t1 = multiply_ntt_poly_by_vector(&c_hat, &t1_hat, parameter_set.core.k)?;
    a_z.checked_sub(&c_t1)
}

fn ntt_vector(vector: &PolyVector) -> DilithiumResult<NttPolyVector> {
    NttPolyVector::from_polys(vector.dimension(), vector.iter().map(Poly::ntt).collect())
}

fn multiply_matrix_by_ntt_vector(
    matrix: &NttMatrix,
    vector_hat: &NttPolyVector,
    parameter_set: ParameterSet,
) -> DilithiumResult<PolyVector> {
    let rows = matrix
        .rows_iter()
        .map(|row| ntt_dot_product(row, vector_hat.polys()).inverse_ntt())
        .collect();
    PolyVector::from_polys(parameter_set.core.k, rows)
}

fn ntt_dot_product(lhs: &[NttPoly], rhs: &[NttPoly]) -> NttPoly {
    let mut sum = NttPoly::zero();
    for (lhs, rhs) in lhs.iter().zip(rhs.iter()) {
        let product = lhs * rhs;
        sum = &sum + &product;
    }
    sum
}

fn multiply_ntt_poly_by_vector(
    poly_hat: &NttPoly,
    vector_hat: &NttPolyVector,
    expected_dimension: usize,
) -> DilithiumResult<PolyVector> {
    let products = vector_hat
        .iter()
        .map(|rhs| (poly_hat * rhs).inverse_ntt())
        .collect();
    PolyVector::from_polys(expected_dimension, products)
}

fn multiply_by_2_power_d(vector: &PolyVector) -> DilithiumResult<PolyVector> {
    let polys = vector
        .iter()
        .map(|poly| {
            Poly::from_coeffs(core::array::from_fn(|index| {
                Coefficient::canonical((poly.coeffs()[index].value() as i64) << D)
            }))
        })
        .collect();
    PolyVector::from_polys(vector.dimension(), polys)
}

#[cfg(test)]
mod tests {
    use dilithium_poc::ml_dsa::Signature;
    use dilithium_poc::params::ML_DSA_65;

    use super::*;

    #[test]
    fn broken_path_accepts_chosen_message_forgery() {
        let key_pair = KeyPair::generate_from_seed(ML_DSA_44, [0x44; 32]).unwrap();
        let message = b"forged message";
        let context = b"phase1";
        let signature = forge_for_target_message(key_pair.public_key(), message, context);

        assert!(broken_verify_no_ctilde(
            key_pair.public_key(),
            message,
            &signature,
            context
        ));
        assert!(!key_pair.public_key().verify(message, &signature, context));
    }

    #[test]
    fn broken_path_still_rejects_structural_failures() {
        let key_pair = KeyPair::generate_from_seed(ML_DSA_44, [0x44; 32]).unwrap();
        let message = b"forged message";
        let context = b"phase1";
        let signature = forge_for_target_message(key_pair.public_key(), message, context);

        let mismatched_signature =
            Signature::from_raw(ML_DSA_65, vec![0u8; ML_DSA_65.sizes.signature_bytes]).unwrap();
        assert!(!broken_verify_no_ctilde(
            key_pair.public_key(),
            message,
            &mismatched_signature,
            context
        ));

        let truncated_signature = Signature::from_raw(
            ML_DSA_44,
            signature.as_bytes()[..signature.as_bytes().len() - 1].to_vec(),
        );
        assert!(truncated_signature.is_err());

        let oversized_context = vec![0u8; 256];
        assert!(!broken_verify_no_ctilde(
            key_pair.public_key(),
            message,
            &signature,
            &oversized_context
        ));

        let z_at_bound = forged_signature_with_z_at_bound();
        assert!(!broken_verify_no_ctilde(
            key_pair.public_key(),
            message,
            &z_at_bound,
            context
        ));
    }
}

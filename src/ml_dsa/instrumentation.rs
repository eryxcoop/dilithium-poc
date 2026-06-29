//! Instrumentation helpers for inspecting nonconforming signing attempts.
//!
//! These helpers are compiled only with the `instrumentation` feature. They
//! expose enough state to study why strict FIPS 204 validation rejects a
//! signing attempt while a deliberately broken verifier-side path might accept
//! it.

use crate::coefficient::Coefficient;
use crate::encoding::{pk_decode, sk_decode};
use crate::error::{DilithiumError, DilithiumResult};
use crate::ml_dsa::{PrivateKey, PublicKey};
use crate::params::{N, ParameterSet};
use crate::poly::PolyVector;
use crate::sampling::{ExpandASeed, expand_a, expand_mask, sample_in_ball};
use crate::xof::shake256;

use super::context::format_message;
use super::sign::{
    ChallengeSeed, MessageRepresentative, SIGNING_RANDOMNESS_BYTES, SigningRandomness,
};

/// A real ML-DSA signing attempt whose only remaining failure is `hint weight > omega`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverweightHintAttempt {
    parameter_set: ParameterSet,
    c_tilde: Vec<u8>,
    z: PolyVector,
    hints: PolyVector,
    hint_weight: usize,
    w_approx: PolyVector,
    randomness: [u8; SIGNING_RANDOMNESS_BYTES],
    kappa: u16,
}

impl OverweightHintAttempt {
    /// Returns the parameter set used for the attempt.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Returns the challenge seed `c_tilde`.
    pub fn c_tilde(&self) -> &[u8] {
        &self.c_tilde
    }

    /// Returns the response vector `z`.
    pub fn z(&self) -> &PolyVector {
        &self.z
    }

    /// Returns the binary hint vector without enforcing the `omega` bound.
    pub fn hints(&self) -> &PolyVector {
        &self.hints
    }

    /// Returns the total number of one coefficients in `h`.
    pub fn hint_weight(&self) -> usize {
        self.hint_weight
    }

    /// Returns the reconstructed `w_approx = A z - c t1 2^d`.
    pub fn w_approx(&self) -> &PolyVector {
        &self.w_approx
    }

    /// Returns the 32-byte signing randomness that produced the attempt.
    pub fn randomness(&self) -> [u8; SIGNING_RANDOMNESS_BYTES] {
        self.randomness
    }

    /// Returns the signing-loop counter `kappa` used for `ExpandMask`.
    pub fn kappa(&self) -> u16 {
        self.kappa
    }
}

/// Searches deterministically for an ML-DSA signing attempt with overweight hints.
///
/// The search uses the real signing equations for `private_key`, `message`, and
/// `context`, but it records the first attempt that satisfies the `z`, `r0`,
/// and `c t0` bounds while producing a binary hint vector whose weight exceeds
/// `omega`. Strict FIPS signing would reject that attempt and continue the
/// rejection loop.
pub fn find_overweight_hint_attempt(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    max_randomness_trials: usize,
    max_kappa_trials: usize,
) -> DilithiumResult<Option<OverweightHintAttempt>> {
    let parameter_set = private_key.parameter_set();
    if public_key.parameter_set() != parameter_set {
        return Err(DilithiumError::InvalidParameterSet);
    }
    let private_parts = sk_decode(private_key.as_bytes(), parameter_set)?;
    let public_parts = pk_decode(public_key.as_bytes(), parameter_set)?;
    let formatted_message = format_message(message, context)?;
    let s1_hat = private_parts.s1.ntt()?;
    let s2_hat = private_parts.s2.ntt()?;
    let t0_hat = private_parts.t0.ntt()?;
    let a_hat = expand_a(ExpandASeed::new(private_parts.rho), parameter_set)?;
    let mu = MessageRepresentative::derive(&private_parts.tr, &formatted_message);

    for randomness_trial in 0..max_randomness_trials {
        let randomness = derived_randomness(randomness_trial as u32);
        let mask_seed = SigningRandomness::from(randomness)
            .expand_mask_seed(&private_parts.secret_key_seed, &mu);

        for kappa_trial in 0..max_kappa_trials {
            let kappa = (kappa_trial * parameter_set.core.l) as u16;
            let y = expand_mask(mask_seed, kappa, parameter_set)?;
            let w = a_hat.multiply_vector(&y, parameter_set)?;
            let w1 = w.high_bits(parameter_set)?;
            let c_tilde = ChallengeSeed::derive(&mu, &w1, parameter_set)?;
            let c = sample_in_ball(c_tilde.as_bytes(), parameter_set)?;
            let c_hat = c.ntt();
            let c_s1 = c_hat.multiply_ntt_vector(&s1_hat, parameter_set.core.l)?;
            let c_s2 = c_hat.multiply_ntt_vector(&s2_hat, parameter_set.core.k)?;
            let z = y.checked_add(&c_s1)?;
            let w_minus_c_s2 = w.checked_sub(&c_s2)?;
            let r0 = w_minus_c_s2.low_bits(parameter_set)?;

            if z.infinity_norm_at_least(parameter_set.core.gamma1 - parameter_set.core.beta)
                || r0.infinity_norm_at_least(parameter_set.core.gamma2 - parameter_set.core.beta)
            {
                continue;
            }

            let c_t0 = c_hat.multiply_ntt_vector(&t0_hat, parameter_set.core.k)?;
            if c_t0.infinity_norm_at_least(parameter_set.core.gamma2) {
                continue;
            }

            let hint_target = w_minus_c_s2.checked_add(&c_t0)?;
            let hints = make_hints_without_omega(parameter_set, &c_t0.neg(), &hint_target)?;
            let hint_weight = hints.binary_weight()?;
            if hint_weight > parameter_set.core.omega as usize {
                let w_approx =
                    reconstruct_w_approx_from_t1(parameter_set, &a_hat, &z, &c, &public_parts.t1)?;
                return Ok(Some(OverweightHintAttempt {
                    parameter_set,
                    c_tilde: c_tilde.as_bytes().to_vec(),
                    z,
                    hints,
                    hint_weight,
                    w_approx,
                    randomness,
                    kappa,
                }));
            }
        }
    }

    Ok(None)
}

/// Runs real ML-DSA verification but skips only the `omega` bound on hints.
pub fn verify_overweight_hint_attempt_without_omega(
    public_key: &PublicKey,
    message: &[u8],
    context: &[u8],
    attempt: &OverweightHintAttempt,
) -> bool {
    let parameter_set = public_key.parameter_set();
    if attempt.parameter_set() != parameter_set {
        return false;
    }

    let formatted_message = match format_message(message, context) {
        Ok(formatted_message) => formatted_message,
        Err(_) => return false,
    };
    let public_parts = match pk_decode(public_key.as_bytes(), parameter_set) {
        Ok(parts) => parts,
        Err(_) => return false,
    };
    let a_hat = match expand_a(ExpandASeed::new(public_parts.rho), parameter_set) {
        Ok(a_hat) => a_hat,
        Err(_) => return false,
    };
    let tr = public_key.hash();
    let mu = MessageRepresentative::derive(&tr, &formatted_message);
    let c = match sample_in_ball(attempt.c_tilde(), parameter_set) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let w_approx = match reconstruct_w_approx_from_t1(
        parameter_set,
        &a_hat,
        attempt.z(),
        &c,
        &public_parts.t1,
    ) {
        Ok(w_approx) => w_approx,
        Err(_) => return false,
    };
    let w1_prime = match use_hints_without_omega(parameter_set, attempt.hints(), &w_approx) {
        Ok(w1_prime) => w1_prime,
        Err(_) => return false,
    };
    let c_tilde_prime = match ChallengeSeed::derive(&mu, &w1_prime, parameter_set) {
        Ok(c_tilde_prime) => c_tilde_prime,
        Err(_) => return false,
    };

    !attempt
        .z()
        .infinity_norm_at_least(parameter_set.core.gamma1 - parameter_set.core.beta)
        && c_tilde_prime.as_bytes() == attempt.c_tilde()
}

fn derived_randomness(counter: u32) -> [u8; SIGNING_RANDOMNESS_BYTES] {
    let mut input = Vec::with_capacity(24);
    input.extend_from_slice(b"verifier_no_omega");
    input.extend_from_slice(&counter.to_le_bytes());
    let digest = shake256(&input, SIGNING_RANDOMNESS_BYTES);
    let mut bytes = [0u8; SIGNING_RANDOMNESS_BYTES];
    bytes.copy_from_slice(&digest);
    bytes
}

fn make_hints_without_omega(
    parameter_set: ParameterSet,
    z: &PolyVector,
    r: &PolyVector,
) -> DilithiumResult<PolyVector> {
    use crate::validation::ensure_dimension;

    ensure_dimension(
        "hint source vector dimension",
        parameter_set.core.k,
        z.dimension(),
    )?;
    ensure_dimension(
        "hint target vector dimension",
        parameter_set.core.k,
        r.dimension(),
    )?;

    let polys = z
        .iter()
        .zip(r.iter())
        .map(|(z_poly, r_poly)| {
            crate::poly::Poly::from_coeffs(core::array::from_fn(|index| {
                let hint = r_poly
                    .coeff(index)
                    .expect("coefficient index is in range")
                    .make_hint(
                        z_poly.coeff(index).expect("coefficient index is in range"),
                        parameter_set.core.gamma2,
                    );
                Coefficient::from(if hint { 1 } else { 0 })
            }))
        })
        .collect();

    PolyVector::from_polys(parameter_set.core.k, polys)
}

fn use_hints_without_omega(
    parameter_set: ParameterSet,
    hints: &PolyVector,
    r: &PolyVector,
) -> DilithiumResult<PolyVector> {
    use crate::validation::ensure_dimension;

    ensure_dimension(
        "hint vector dimension",
        parameter_set.core.k,
        hints.dimension(),
    )?;
    ensure_dimension(
        "hint target vector dimension",
        parameter_set.core.k,
        r.dimension(),
    )?;
    hints.binary_weight()?;

    let mut polys = Vec::with_capacity(hints.dimension());
    for (hint_poly, r_poly) in hints.iter().zip(r.iter()) {
        let mut coeffs = [Coefficient::default(); N];
        for (index, coefficient) in coeffs.iter_mut().enumerate() {
            let hint = hint_poly
                .coeff(index)
                .expect("coefficient index is in range")
                .value();
            if hint != 0 && hint != 1 {
                return Err(DilithiumError::ValueOutOfRange {
                    item: "hint coefficient",
                    min: 0,
                    max: 1,
                    actual: hint as i64,
                });
            }
            let adjusted = r_poly
                .coeff(index)
                .expect("coefficient index is in range")
                .use_hint(hint == 1, parameter_set.core.gamma2);
            *coefficient = Coefficient::from(adjusted as i32);
        }
        polys.push(crate::poly::Poly::from_coeffs(coeffs));
    }

    PolyVector::from_polys(parameter_set.core.k, polys)
}

fn reconstruct_w_approx_from_t1(
    parameter_set: ParameterSet,
    a_hat: &crate::poly::NttMatrix,
    z: &PolyVector,
    c: &crate::poly::Poly,
    t1: &PolyVector,
) -> DilithiumResult<PolyVector> {
    let z_hat = z.ntt()?;
    let a_z = a_hat.multiply_ntt_vector(&z_hat, parameter_set)?;
    let c_hat = c.ntt();
    let t1_times_2d = t1.multiply_by_2_power_d()?;
    let t1_hat = t1_times_2d.ntt()?;
    let c_t1 = c_hat.multiply_ntt_vector(&t1_hat, parameter_set.core.k)?;
    a_z.checked_sub(&c_t1)
}

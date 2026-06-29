//! `toy_dense_hint_forgery`: overweight hints forge a toy signature.

use crate::shared::{
    ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript, sample_ternary_seed,
    toy_u8_challenge_seed, toy_u8_message_representative,
};
use crate::toy::{
    ToyHintSignature, ToyParams, ToyPoly, ToyPublicKey, bits_from_mask, dense_hint_signing_key,
    first_hint_positions, hint_weight, reconstruct_w_approx, use_hints,
};

const DEGREE: usize = 8;
const MODULUS: i64 = 97;
const GAMMA2: i64 = 8;
const OMEGA: usize = 2;
const Z_BOUND: i64 = 3;
const CHALLENGE_MODULUS: u8 = 16;

/// Runs a toy forgery demo that uses only overweight hints.
pub fn run() -> ChallengeRun {
    let params = ToyParams::new(DEGREE, MODULUS).expect("toy params should be valid");
    let signing_key = dense_hint_signing_key(params);
    let message = b"classroom dense hint forgery";
    let context = b"classroom";
    let replay_message = b"different message";
    let mu = toy_u8_message_representative(message, context, CHALLENGE_MODULUS);
    let z_candidates = generate_z_candidates(params);
    let forgery =
        find_overweight_hint_forgery(&signing_key.public_key, message, context, &z_candidates)
            .expect("deterministic search should find a toy forgery");

    let strict_accepts = strict_verify(&signing_key.public_key, message, context, &forgery);
    let vulnerable_accepts =
        vulnerable_verify_without_omega(&signing_key.public_key, message, context, &forgery);
    let replay_accepts =
        vulnerable_verify_without_omega(&signing_key.public_key, replay_message, context, &forgery);
    let success = vulnerable_accepts && !strict_accepts && !replay_accepts;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy verifier uses n = {DEGREE}, q = {MODULUS}, gamma2 = {GAMMA2}, omega = {OMEGA}, and ||z||∞ < {Z_BOUND}. The attacker knows only the public pair (a, t1), with centered t1 = {:?}.",
                signing_key.public_key.t.centered_coeffs()
            ),
        )
        .step(
            "Public-data search",
            format!(
                "For target mu = {mu}, the attacker enumerates {} bounded z candidates, all 2^{DEGREE} binary hint masks, and c_tilde in [0, {}). No private key material is used during the search.",
                z_candidates.len(),
                CHALLENGE_MODULUS
            ),
        )
        .step(
            "Found forgery",
            format!(
                "The forged signature uses centered z = {:?}, weight(h) = {}, c_tilde = {}, and first hinted positions {:?}. Its reconstructed w_approx has centered coefficients {:?}.",
                forgery.z.centered_coeffs(),
                hint_weight(&forgery.hints),
                forgery.c_tilde,
                first_hint_positions(&forgery.hints, 6),
                forgery.w_approx.centered_coeffs()
            ),
        )
        .step(
            "Verifier split",
            format!(
                "The vulnerable verifier recomputes c from c_tilde, rebuilds w_approx = a·z - c·t1, applies UseHint coefficientwise, and checks c_tilde' = H(mu || w1'). It accepts: vulnerable_accepts = {vulnerable_accepts}. The strict verifier rejects earlier because weight(h) = {} > omega = {OMEGA}.",
                hint_weight(&forgery.hints)
            ),
        )
        .step(
            "Binding still works",
            format!(
                "Replaying the same overweight-hint forgery on {:?} fails even without the omega check: replay_accepts = {replay_accepts}. The exploit is not 'skip Fiat-Shamir'; it is 'give UseHint too many attacker-controlled corrections'.",
                String::from_utf8_lossy(replay_message)
            ),
        )
        .step(
            "FIPS defense",
            "Verifier-side hint validation must reject weight(h) > omega before UseHint can sculpt too many high-bit coordinates. Sparse hints are part of the signature language, not optional metadata.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "toy_dense_hint_forgery",
            "Toy Forgery From Overweight Hints",
            ChallengeMode::ToyParams,
            "accepts dense hint vectors with weight greater than omega",
        ),
        transcript,
        success,
    )
}

fn find_overweight_hint_forgery(
    public_key: &ToyPublicKey,
    message: &[u8],
    context: &[u8],
    z_candidates: &[ToyPoly],
) -> Option<ToyHintSignature> {
    let mu = toy_u8_message_representative(message, context, CHALLENGE_MODULUS);

    for z in z_candidates {
        if z.infinity_norm() >= Z_BOUND {
            continue;
        }

        for c_tilde in 0..CHALLENGE_MODULUS {
            let c = sample_ternary_seed(c_tilde);
            let w_approx = reconstruct_w_approx(public_key, z, c);

            for mask in 0usize..(1usize << DEGREE) {
                let hints = bits_from_mask(mask, DEGREE);
                if hint_weight(&hints) <= OMEGA {
                    continue;
                }

                let w1_prime = use_hints(&w_approx, &hints, GAMMA2);
                if toy_u8_challenge_seed(mu, &w1_prime, CHALLENGE_MODULUS) == c_tilde {
                    return Some(ToyHintSignature {
                        c_tilde,
                        z: z.clone(),
                        hints,
                        w_approx,
                    });
                }
            }
        }
    }

    None
}

fn strict_verify(
    public_key: &ToyPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &ToyHintSignature,
) -> bool {
    if hint_weight(&signature.hints) > OMEGA {
        return false;
    }
    vulnerable_verify_without_omega(public_key, message, context, signature)
}

fn vulnerable_verify_without_omega(
    public_key: &ToyPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &ToyHintSignature,
) -> bool {
    if signature.z.infinity_norm() >= Z_BOUND {
        return false;
    }
    if signature.hints.len() != DEGREE {
        return false;
    }

    let mu = toy_u8_message_representative(message, context, CHALLENGE_MODULUS);
    let c = sample_ternary_seed(signature.c_tilde);
    let w_approx = reconstruct_w_approx(public_key, &signature.z, c);
    let w1_prime = use_hints(&w_approx, &signature.hints, GAMMA2);
    toy_u8_challenge_seed(mu, &w1_prime, CHALLENGE_MODULUS) == signature.c_tilde
}

fn generate_z_candidates(params: ToyParams) -> Vec<ToyPoly> {
    let patterns: [[i64; DEGREE]; 15] = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [1, -1, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 0, 0, 0, 0],
        [1, 1, -1, 0, 0, 0, 0, 0],
        [1, 0, 1, 0, 0, 0, 0, 0],
        [1, -1, 1, 0, 0, 0, 0, 0],
        [1, 1, 0, -1, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
        [0, 1, -1, 0, 0, 0, 0, 0],
        [0, 1, 1, 0, 0, 0, 0, 0],
        [0, 1, 1, -1, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, -1, 0, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 0, 0],
    ];
    let mut candidates = Vec::new();

    for shift in 0..DEGREE {
        for pattern in patterns {
            for scale in 1..=Z_BOUND {
                let rotated = rotate_pattern(pattern, shift)
                    .into_iter()
                    .map(|coefficient| coefficient * scale)
                    .collect::<Vec<_>>();
                let candidate =
                    ToyPoly::from_coeffs(params, rotated).expect("pattern length is valid");
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates
}

fn rotate_pattern(pattern: [i64; DEGREE], shift: usize) -> [i64; DEGREE] {
    let mut rotated = [0i64; DEGREE];
    for (index, coefficient) in pattern.into_iter().enumerate() {
        rotated[(index + shift) % DEGREE] = coefficient;
    }
    rotated
}

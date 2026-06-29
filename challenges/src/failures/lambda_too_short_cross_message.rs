//! `lambda_too_short_cross_message`: a 24-bit challenge enables cross-message forgery.

use crate::shared::{
    ChallengeMetadata, ChallengeMode, ChallengeRun, Transcript, random_bounded_polys,
    short_prefix_24, toy_full_challenge_seed, toy_message_representative,
};
use crate::toy::{
    ToyChallengeSignature, ToyParams, ToyPoly, ToyPublicKey, ToySigningKey, high_bits_vector,
    reconstruct_w_approx, sample_ternary_challenge,
};

const DEGREE: usize = 8;
const MODULUS: i64 = 257;
const GAMMA2: i64 = 8;
const Y_BOUND: i64 = 3;
const Z_BOUND: i64 = 5;
const SIGNED_MESSAGE_CANDIDATES: usize = 12_000;
const FORGED_MESSAGE_CANDIDATES: usize = 30_000;
const SIGNED_MESSAGE_SEED: u64 = 0x00aa_aa11_2233_4455;
const FORGED_MESSAGE_SEED: u64 = 0x00bb_bb66_7788_99aa;
const FULL_CHALLENGE_BYTES: usize = 4;
const SHORT_CHALLENGE_BYTES: usize = 3;

/// Runs the short-`λ` cross-message classroom demo.
pub fn run() -> ChallengeRun {
    let params = ToyParams::new(DEGREE, MODULUS).expect("toy params should be valid");
    let signing_key = toy_signing_key(params);
    let signed_message = b"signed classroom note";
    let forged_message = b"unsigned target note";
    let context = b"classroom";
    let collision =
        find_cross_message_collision(&signing_key, signed_message, forged_message, context)
            .expect("deterministic search should find a cross-message collision");

    let signed_strict_accepts = strict_verify(
        &signing_key.public_key,
        signed_message,
        context,
        &collision.signed_signature,
    );
    let forged_strict_accepts = strict_verify(
        &signing_key.public_key,
        forged_message,
        context,
        &collision.forged_signature,
    );
    let forged_vulnerable_accepts = vulnerable_verify_with_short_lambda(
        &signing_key.public_key,
        forged_message,
        context,
        &collision.forged_signature,
    );
    let success = signed_strict_accepts && forged_vulnerable_accepts && !forged_strict_accepts;

    let transcript = Transcript::new()
        .step(
            "Setup",
            format!(
                "Toy verifier keeps the signer/verification shape but truncates c̃ to {SHORT_CHALLENGE_BYTES} bytes (24 bits) instead of using the full {FULL_CHALLENGE_BYTES}-byte challenge hash. The signer legitimately signs {:?}; the attacker targets the unsigned message {:?}.",
                String::from_utf8_lossy(signed_message),
                String::from_utf8_lossy(forged_message)
            ),
        )
        .step(
            "Collision search",
            format!(
                "The signer side enumerates {SIGNED_MESSAGE_CANDIDATES} bounded y candidates for the signed message, while the attacker enumerates {FORGED_MESSAGE_CANDIDATES} bounded z candidates for the forged message. The first collision found shares short c̃ prefix {:02x?} but differs in the last byte: signed full c̃ = {:02x?}, forged recomputed full c̃ = {:02x?}.",
                &collision.signed_signature.c_tilde[..SHORT_CHALLENGE_BYTES],
                collision.signed_signature.c_tilde,
                collision.forged_full_recomputed
            ),
        )
        .step(
            "Legitimate signature",
            format!(
                "The signed message uses challenge c = {}, centered z = {:?}, and verifies even under the strict full-length check.",
                sample_ternary_challenge(collision.signed_signature.c_tilde[0]),
                collision.signed_signature.z.centered_coeffs()
            ),
        )
        .step(
            "Forgery",
            format!(
                "The attacker reuses the signed message's full c̃ on the unsigned message, but swaps in centered z = {:?}. The forged transcript reconstructs a different w₁′ whose full hash is {:02x?}, yet it keeps the same first 24 bits.",
                collision.forged_signature.z.centered_coeffs(),
                collision.forged_full_recomputed
            ),
        )
        .step(
            "Verifier split",
            format!(
                "The vulnerable verifier checks only the first 24 bits, so forged_vulnerable_accepts = {forged_vulnerable_accepts}. The strict verifier compares the full 32-bit c̃ and rejects: forged_strict_accepts = {forged_strict_accepts}."
            ),
        )
        .step(
            "FIPS defense",
            "The λ-sized challenge output is part of Fiat-Shamir soundness. Truncating c̃ makes cross-message transcript collisions searchable, so a verifier can accept a signature for a message that was never signed.",
        );

    ChallengeRun::new(
        ChallengeMetadata::new(
            "lambda_too_short_cross_message",
            "Cross-Message Forgery From Short λ",
            ChallengeMode::ToyParams,
            "truncates c̃ below the λ-sized challenge length",
        ),
        transcript,
        success,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CollisionOutcome {
    signed_signature: ToyChallengeSignature<FULL_CHALLENGE_BYTES>,
    forged_signature: ToyChallengeSignature<FULL_CHALLENGE_BYTES>,
    forged_full_recomputed: [u8; FULL_CHALLENGE_BYTES],
}

fn toy_signing_key(params: ToyParams) -> ToySigningKey {
    let a = ToyPoly::from_coeffs(params, [3, 1, 0, 2, 0, 1, 0, 4]).expect("length is valid");
    let secret =
        ToyPoly::from_coeffs(params, [1, -2, 2, 0, -1, 1, 0, 2]).expect("length is valid");
    let t = a.checked_mul(&secret).expect("matching toy params");

    ToySigningKey {
        public_key: ToyPublicKey { a, t },
        secret,
    }
}

fn find_cross_message_collision(
    signing_key: &ToySigningKey,
    signed_message: &[u8],
    forged_message: &[u8],
    context: &[u8],
) -> Option<CollisionOutcome> {
    use std::collections::HashMap;

    let signed_mu = toy_message_representative(signed_message, context);
    let forged_mu = toy_message_representative(forged_message, context);
    let mut signed_candidates =
        HashMap::<(i64, u32), Vec<ToyChallengeSignature<FULL_CHALLENGE_BYTES>>>::new();

    for y in random_bounded_polys(
        signing_key.public_key.a.params(),
        Y_BOUND,
        SIGNED_MESSAGE_CANDIDATES,
        SIGNED_MESSAGE_SEED,
    ) {
        let w = signing_key
            .public_key
            .a
            .checked_mul(&y)
            .expect("matching toy params");
        let w1 = high_bits_vector(&w, GAMMA2);
        let c_tilde_full = toy_full_challenge_seed(&signed_mu, &w1);
        let c = sample_ternary_challenge(c_tilde_full[0]);
        let z = y
            .checked_add(&signing_key.secret.scalar_mul(c))
            .expect("matching toy params");
        if z.infinity_norm() > Z_BOUND {
            continue;
        }
        signed_candidates
            .entry((c, short_prefix_24(&c_tilde_full)))
            .or_default()
            .push(ToyChallengeSignature { c_tilde: c_tilde_full, z });
    }

    for z in random_bounded_polys(
        signing_key.public_key.a.params(),
        Z_BOUND,
        FORGED_MESSAGE_CANDIDATES,
        FORGED_MESSAGE_SEED,
    ) {
        if z.infinity_norm() > Z_BOUND {
            continue;
        }

        for c in [-1, 0, 1] {
            let w_approx = reconstruct_w_approx(&signing_key.public_key, &z, c);
            let w1 = high_bits_vector(&w_approx, GAMMA2);
            let forged_full = toy_full_challenge_seed(&forged_mu, &w1);
            if let Some(signed_signature) = signed_candidates
                .get(&(c, short_prefix_24(&forged_full)))
                .and_then(|signed_bucket| {
                    signed_bucket
                        .iter()
                        .find(|signed_signature| signed_signature.c_tilde != forged_full)
                })
            {
                return Some(CollisionOutcome {
                    signed_signature: signed_signature.clone(),
                    forged_signature: ToyChallengeSignature {
                        c_tilde: signed_signature.c_tilde,
                        z: z.clone(),
                    },
                    forged_full_recomputed: forged_full,
                });
            }
        }
    }

    None
}

fn strict_verify(
    public_key: &ToyPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &ToyChallengeSignature<FULL_CHALLENGE_BYTES>,
) -> bool {
    if signature.z.infinity_norm() > Z_BOUND {
        return false;
    }

    let mu = toy_message_representative(message, context);
    let c = sample_ternary_challenge(signature.c_tilde[0]);
    let w_approx = reconstruct_w_approx(public_key, &signature.z, c);
    let full_recomputed = toy_full_challenge_seed(&mu, &high_bits_vector(&w_approx, GAMMA2));

    full_recomputed == signature.c_tilde
}

fn vulnerable_verify_with_short_lambda(
    public_key: &ToyPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &ToyChallengeSignature<FULL_CHALLENGE_BYTES>,
) -> bool {
    if signature.z.infinity_norm() > Z_BOUND {
        return false;
    }

    let mu = toy_message_representative(message, context);
    let c = sample_ternary_challenge(signature.c_tilde[0]);
    let w_approx = reconstruct_w_approx(public_key, &signature.z, c);
    let full_recomputed = toy_full_challenge_seed(&mu, &high_bits_vector(&w_approx, GAMMA2));

    short_prefix_24(&full_recomputed) == short_prefix_24(&signature.c_tilde)
}

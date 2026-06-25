//! ACVP sigGen vector checks.

use crate::ml_dsa::PrivateKey;

use super::fixtures::{SIGGEN_EXPECTED, SIGGEN_PROMPT};
use super::models::{AcvpFile, SigGenExpectedGroup, SigGenPromptGroup};
use super::support::{
    cases_by_id, fixed_bytes, groups_by_id, hex_bytes, is_pure_external, parameter_set, parse_json,
    required,
};

#[test]
fn acvp_siggen_pure_external_vectors_match_official_expected_results() {
    let prompt: AcvpFile<SigGenPromptGroup> = parse_json(SIGGEN_PROMPT);
    let expected: AcvpFile<SigGenExpectedGroup> = parse_json(SIGGEN_EXPECTED);
    let expected_by_group = groups_by_id(expected.test_groups);

    let mut checked = 0usize;
    for group in prompt.test_groups {
        if !is_pure_external(&group.pre_hash, &group.signature_interface) {
            continue;
        }

        let parameter_set = parameter_set(required(&group.parameter_set));
        let expected_group = expected_by_group
            .get(&group.tg_id)
            .expect("expected sigGen group is present");
        let expected_by_case = cases_by_id(&expected_group.tests);

        for test in group.tests {
            let private_key = PrivateKey::from_raw(parameter_set, hex_bytes(required(&test.sk)))
                .expect("ACVP private key has valid raw length");
            let message = hex_bytes(required(&test.message));
            let context = hex_bytes(required(&test.context));
            let signature = if group.deterministic {
                private_key.sign_deterministic_for_test(&message, &context)
            } else {
                private_key.sign_with_randomness_for_test(
                    &message,
                    &context,
                    fixed_bytes(required(&test.rnd)),
                )
            }
            .expect("sigGen vector runs");

            let expected_case = expected_by_case
                .get(&test.tc_id)
                .expect("expected sigGen case is present");
            assert_eq!(
                signature.as_bytes(),
                hex_bytes(&expected_case.signature),
                "ACVP sigGen tgId={} tcId={} signature mismatch",
                group.tg_id,
                test.tc_id,
            );
            checked += 1;
        }
    }

    assert_eq!(checked, 90);
}

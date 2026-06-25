//! ACVP sigVer vector checks.

use crate::ml_dsa::{PublicKey, Signature};
use crate::params::ParameterSet;

use super::fixtures::{SIGVER_EXPECTED, SIGVER_PROMPT};
use super::models::{AcvpFile, SigVerExpectedGroup, SigVerPromptCase, SigVerPromptGroup};
use super::support::{
    cases_by_id, groups_by_id, hex_bytes, is_pure_external, parameter_set, parse_json, required,
};

#[test]
fn acvp_sigver_pure_external_vectors_match_official_expected_results() {
    let prompt: AcvpFile<SigVerPromptGroup> = parse_json(SIGVER_PROMPT);
    let expected: AcvpFile<SigVerExpectedGroup> = parse_json(SIGVER_EXPECTED);
    let expected_by_group = groups_by_id(expected.test_groups);

    let mut checked = 0usize;
    for group in prompt.test_groups {
        if !is_pure_external(&group.pre_hash, &group.signature_interface) {
            continue;
        }

        let parameter_set = parameter_set(required(&group.parameter_set));
        let expected_group = expected_by_group
            .get(&group.tg_id)
            .expect("expected sigVer group is present");
        let expected_by_case = cases_by_id(&expected_group.tests);

        for test in group.tests {
            let expected_case = expected_by_case
                .get(&test.tc_id)
                .expect("expected sigVer case is present");
            let actual = verify_acvp_signature(parameter_set, &test);

            assert_eq!(
                actual, expected_case.test_passed,
                "ACVP sigVer tgId={} tcId={} result mismatch",
                group.tg_id, test.tc_id,
            );
            checked += 1;
        }
    }

    assert_eq!(checked, 45);
}

fn verify_acvp_signature(parameter_set: ParameterSet, test: &SigVerPromptCase) -> bool {
    let public_key = match PublicKey::from_raw(parameter_set, hex_bytes(required(&test.pk))) {
        Ok(public_key) => public_key,
        Err(_) => return false,
    };
    let signature = match Signature::from_raw(parameter_set, hex_bytes(required(&test.signature))) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    public_key.verify(
        &hex_bytes(required(&test.message)),
        &signature,
        &hex_bytes(required(&test.context)),
    )
}

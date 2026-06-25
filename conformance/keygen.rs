//! ACVP keyGen vector checks.

use crate::ml_dsa::KeyPair;

use super::fixtures::{KEYGEN_EXPECTED, KEYGEN_PROMPT};
use super::models::{AcvpFile, KeyGenExpectedGroup, KeyGenPromptGroup};
use super::support::{
    cases_by_id, fixed_bytes, groups_by_id, hex_bytes, parameter_set, parse_json,
};

#[test]
fn acvp_keygen_vectors_match_official_expected_results() {
    let prompt: AcvpFile<KeyGenPromptGroup> = parse_json(KEYGEN_PROMPT);
    let expected: AcvpFile<KeyGenExpectedGroup> = parse_json(KEYGEN_EXPECTED);
    let expected_by_group = groups_by_id(expected.test_groups);

    let mut checked = 0usize;
    for group in prompt.test_groups {
        let parameter_set = parameter_set(&group.parameter_set);
        let expected_group = expected_by_group
            .get(&group.tg_id)
            .expect("expected keyGen group is present");
        let expected_by_case = cases_by_id(&expected_group.tests);

        for test in group.tests {
            let expected_case = expected_by_case
                .get(&test.tc_id)
                .expect("expected keyGen case is present");
            let seed = fixed_bytes::<32>(&test.seed);
            let key_pair =
                KeyPair::generate_from_seed(parameter_set, seed).expect("keyGen vector runs");

            assert_eq!(
                key_pair.public_key().as_bytes(),
                hex_bytes(&expected_case.pk),
                "ACVP keyGen tgId={} tcId={} pk mismatch",
                group.tg_id,
                test.tc_id,
            );
            assert_eq!(
                key_pair.private_key().as_bytes(),
                hex_bytes(&expected_case.sk),
                "ACVP keyGen tgId={} tcId={} sk mismatch",
                group.tg_id,
                test.tc_id,
            );
            checked += 1;
        }
    }

    assert_eq!(checked, 75);
}

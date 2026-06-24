//! Scope checks for the ACVP conformance runner.

use super::fixtures::{SIGGEN_PROMPT, SIGVER_PROMPT};
use super::models::{AcvpFile, SigGenPromptGroup, SigVerPromptGroup};
use super::support::{is_pure_external, parse_json};

#[test]
fn acvp_vector_scope_is_explicit() {
    let siggen: AcvpFile<SigGenPromptGroup> = parse_json(SIGGEN_PROMPT);
    let sigver: AcvpFile<SigVerPromptGroup> = parse_json(SIGVER_PROMPT);

    let siggen_pure_external = siggen
        .test_groups
        .iter()
        .filter(|group| is_pure_external(&group.pre_hash, &group.signature_interface))
        .count();
    let sigver_pure_external = sigver
        .test_groups
        .iter()
        .filter(|group| is_pure_external(&group.pre_hash, &group.signature_interface))
        .count();

    assert_eq!(siggen_pure_external, 6);
    assert_eq!(sigver_pure_external, 3);
}

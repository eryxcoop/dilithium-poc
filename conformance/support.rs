//! Shared helpers for ACVP conformance tests.

use std::collections::HashMap;

use serde::Deserialize;

use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ParameterSet};

use super::models::{HasCaseId, HasGroupId};

pub(super) fn is_pure_external(
    pre_hash: &Option<String>,
    signature_interface: &Option<String>,
) -> bool {
    pre_hash.as_deref() == Some("pure") && signature_interface.as_deref() == Some("external")
}

pub(super) fn parameter_set(name: &str) -> ParameterSet {
    match name {
        "ML-DSA-44" => ML_DSA_44,
        "ML-DSA-65" => ML_DSA_65,
        "ML-DSA-87" => ML_DSA_87,
        _ => panic!("unknown ML-DSA parameter set: {name}"),
    }
}

pub(super) fn required(value: &Option<String>) -> &str {
    value
        .as_deref()
        .expect("filtered ACVP group has required field")
}

pub(super) fn parse_json<T>(json: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json).expect("ACVP JSON fixture parses")
}

pub(super) fn groups_by_id<T>(groups: Vec<T>) -> HashMap<u32, T>
where
    T: HasGroupId,
{
    groups
        .into_iter()
        .map(|group| (group.group_id(), group))
        .collect()
}

pub(super) fn cases_by_id<T>(cases: &[T]) -> HashMap<u32, &T>
where
    T: HasCaseId,
{
    cases.iter().map(|case| (case.case_id(), case)).collect()
}

pub(super) fn fixed_bytes<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_bytes(hex);
    bytes
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

pub(super) fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "hex fixture length must be even"
    );

    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex fixture"))
        .collect()
}

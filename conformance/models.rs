//! Minimal ACVP JSON models used by the conformance runner.

use serde::Deserialize;

pub(super) trait HasGroupId {
    fn group_id(&self) -> u32;
}

pub(super) trait HasCaseId {
    fn case_id(&self) -> u32;
}

#[derive(Debug, Deserialize)]
pub(super) struct AcvpFile<T> {
    #[serde(rename = "testGroups")]
    pub(super) test_groups: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub(super) struct KeyGenPromptGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    #[serde(rename = "parameterSet")]
    pub(super) parameter_set: String,
    pub(super) tests: Vec<KeyGenPromptCase>,
}

impl HasGroupId for KeyGenPromptGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct KeyGenPromptCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    pub(super) seed: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct KeyGenExpectedGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    pub(super) tests: Vec<KeyGenExpectedCase>,
}

impl HasGroupId for KeyGenExpectedGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct KeyGenExpectedCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    pub(super) pk: String,
    pub(super) sk: String,
}

impl HasCaseId for KeyGenExpectedCase {
    fn case_id(&self) -> u32 {
        self.tc_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigGenPromptGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    #[serde(rename = "parameterSet")]
    pub(super) parameter_set: Option<String>,
    #[serde(default)]
    pub(super) deterministic: bool,
    #[serde(rename = "preHash")]
    pub(super) pre_hash: Option<String>,
    #[serde(rename = "signatureInterface")]
    pub(super) signature_interface: Option<String>,
    pub(super) tests: Vec<SigGenPromptCase>,
}

impl HasGroupId for SigGenPromptGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigGenPromptCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    pub(super) message: Option<String>,
    pub(super) sk: Option<String>,
    pub(super) context: Option<String>,
    pub(super) rnd: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SigGenExpectedGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    pub(super) tests: Vec<SigGenExpectedCase>,
}

impl HasGroupId for SigGenExpectedGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigGenExpectedCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    pub(super) signature: String,
}

impl HasCaseId for SigGenExpectedCase {
    fn case_id(&self) -> u32 {
        self.tc_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigVerPromptGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    #[serde(rename = "parameterSet")]
    pub(super) parameter_set: Option<String>,
    #[serde(rename = "preHash")]
    pub(super) pre_hash: Option<String>,
    #[serde(rename = "signatureInterface")]
    pub(super) signature_interface: Option<String>,
    pub(super) tests: Vec<SigVerPromptCase>,
}

impl HasGroupId for SigVerPromptGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigVerPromptCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    pub(super) pk: Option<String>,
    pub(super) message: Option<String>,
    pub(super) context: Option<String>,
    pub(super) signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SigVerExpectedGroup {
    #[serde(rename = "tgId")]
    pub(super) tg_id: u32,
    pub(super) tests: Vec<SigVerExpectedCase>,
}

impl HasGroupId for SigVerExpectedGroup {
    fn group_id(&self) -> u32 {
        self.tg_id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SigVerExpectedCase {
    #[serde(rename = "tcId")]
    pub(super) tc_id: u32,
    #[serde(rename = "testPassed")]
    pub(super) test_passed: bool,
}

impl HasCaseId for SigVerExpectedCase {
    fn case_id(&self) -> u32 {
        self.tc_id
    }
}

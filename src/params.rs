//! FIPS 204 parameter-set metadata.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterSetId {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterSet {
    pub id: ParameterSetId,
    pub name: &'static str,
    pub security_category: u8,
    pub k: usize,
    pub l: usize,
    pub eta: u32,
    pub tau: u32,
    pub lambda: u32,
    pub gamma1: u32,
    pub gamma2: u32,
    pub beta: u32,
    pub omega: u32,
    pub public_key_bytes: usize,
    pub private_key_bytes: usize,
    pub signature_bytes: usize,
}

pub const N: usize = 256;
pub const Q: u32 = 8_380_417;
pub const ZETA: u32 = 1_753;
pub const D: u32 = 13;

pub const ML_DSA_44: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa44,
    name: "ML-DSA-44",
    security_category: 2,
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    beta: 78,
    omega: 80,
    public_key_bytes: 1_312,
    private_key_bytes: 2_560,
    signature_bytes: 2_420,
};

pub const ML_DSA_65: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa65,
    name: "ML-DSA-65",
    security_category: 3,
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    beta: 196,
    omega: 55,
    public_key_bytes: 1_952,
    private_key_bytes: 4_032,
    signature_bytes: 3_309,
};

pub const ML_DSA_87: ParameterSet = ParameterSet {
    id: ParameterSetId::MlDsa87,
    name: "ML-DSA-87",
    security_category: 5,
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    beta: 120,
    omega: 75,
    public_key_bytes: 2_592,
    private_key_bytes: 4_896,
    signature_bytes: 4_627,
};

pub const PARAMETER_SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

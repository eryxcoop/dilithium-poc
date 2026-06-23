//! Public wrapper types for raw FIPS 204 encodings.

use crate::error::{Error, Result};
use crate::params::ParameterSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    parameter_set: ParameterSet,
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> Result<Self> {
        ensure_len("public key", parameter_set.public_key_bytes, bytes.len())?;
        Ok(Self {
            parameter_set,
            bytes,
        })
    }

    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PrivateKey {
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> Result<Self> {
        ensure_len("private key", parameter_set.private_key_bytes, bytes.len())?;
        Ok(Self {
            parameter_set,
            bytes,
        })
    }

    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Signature {
    pub fn from_raw(parameter_set: ParameterSet, bytes: Vec<u8>) -> Result<Self> {
        ensure_len("signature", parameter_set.signature_bytes, bytes.len())?;
        Ok(Self {
            parameter_set,
            bytes,
        })
    }

    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn ensure_len(item: &'static str, expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual,
            item,
        })
    }
}

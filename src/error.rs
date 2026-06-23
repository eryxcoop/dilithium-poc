//! Error types for the ML-DSA POC.

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLength {
        expected: usize,
        actual: usize,
        item: &'static str,
    },
    InvalidParameterSet,
    Unsupported(&'static str),
}

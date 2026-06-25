//! ACVP conformance tests backed by official NIST CAVP vectors.
//!
//! The vectors live beside this runner rather than in `tests/` so conformance
//! data is kept separate from ordinary unit tests. The source files are copied
//! from:
//!
//! <https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>

mod fixtures;
mod keygen;
mod models;
#[cfg(feature = "pkix")]
mod pkix;
mod scope;
mod siggen;
mod sigver;
mod support;

//! FIPS 204 parameter-set metadata.

mod constants;
mod core;
mod ids;
mod sets;
mod sizes;

pub use constants::{D, N, Q, ZETA};
pub use core::CoreParams;
pub use ids::ParameterSetId;
pub use sets::{ML_DSA_44, ML_DSA_65, ML_DSA_87, PARAMETER_SETS, ParameterSet};
pub use sizes::EncodedSizes;

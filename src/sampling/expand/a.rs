//! `ExpandA` for the public ML-DSA matrix.
//!
//! ML-DSA does not store or transmit the full public matrix `A`; instead, the
//! public key contains a 32-byte seed `ρ`. `ExpandA(ρ)` deterministically
//! reconstructs the same pseudo-random matrix whenever key generation, signing,
//! or verification needs it.
//!
//! FIPS 204 defines the expanded matrix as `Â`, a `k × l` matrix whose
//! entries are already sampled in the NTT domain `T_q`. That is why this module
//! returns [`NttMatrix`] rather than a coefficient-domain `PolyMatrix`.

use crate::error::DilithiumResult;
use crate::params::ParameterSet;
use crate::poly::NttMatrix;
use crate::sampling::constants::{
    EXPAND_A_SEED_BYTES, ExpandASeed, REJ_NTT_POLY_SEED_BYTES, RejNttPolySeed,
};
use crate::sampling::limits::SamplingLimits;
use crate::sampling::rejection::rej_ntt_poly_with_limits;
use crate::sampling::report::{Sampled, SamplingReport};

/// FIPS 204 Algorithm 32, `ExpandA(ρ)`.
///
/// This convenience wrapper runs without optional Table 3 caps and returns only
/// the sampled public matrix `Â`.
pub fn expand_a(seed: ExpandASeed, parameter_set: ParameterSet) -> DilithiumResult<NttMatrix> {
    Ok(expand_a_with_limits(seed, parameter_set, SamplingLimits::default())?.into_value())
}

/// `ExpandA` with optional limits and aggregated instrumentation.
///
/// `ExpandA` builds the `k × l` public matrix `Â` in row-major order. The
/// dimensions come from the selected parameter set:
///
/// - ML-DSA-44 uses `4 × 4`.
/// - ML-DSA-65 uses `6 × 5`.
/// - ML-DSA-87 uses `8 × 7`.
///
/// For each matrix entry `(row, col)`, FIPS derives a 34-byte `RejNTTPoly` seed
/// by appending one byte of column index and one byte of row index to `ρ`:
///
/// ```text
/// ρ || IntegerToBytes(col, 1) || IntegerToBytes(row, 1)
/// ```
///
/// The `col, row` order is normative. Each derived seed is then passed to
/// `RejNTTPoly`, which uses `G = SHAKE128` to collect 256 accepted coefficients
/// below `q`. The resulting entry is an [`crate::poly::NttPoly`].
///
/// The returned [`Sampled`] report accumulates the instrumentation from every
/// `RejNTTPoly` call: loop iterations, XOF bytes, and rejected candidates.
pub fn expand_a_with_limits(
    seed: ExpandASeed,
    parameter_set: ParameterSet,
    limits: SamplingLimits,
) -> DilithiumResult<Sampled<NttMatrix>> {
    limits.validate()?;

    let mut polys = Vec::with_capacity(parameter_set.core.k * parameter_set.core.l);
    let mut report = SamplingReport::default();

    for row in 0..parameter_set.core.k {
        for col in 0..parameter_set.core.l {
            let mut derived_seed = [0u8; REJ_NTT_POLY_SEED_BYTES];
            derived_seed[..EXPAND_A_SEED_BYTES].copy_from_slice(seed.as_bytes());
            derived_seed[EXPAND_A_SEED_BYTES] = col as u8;
            derived_seed[EXPAND_A_SEED_BYTES + 1] = row as u8;

            let sampled = rej_ntt_poly_with_limits(RejNttPolySeed::new(derived_seed), limits)?;
            let (value, sampled_report) = sampled.into_parts();
            report.absorb(sampled_report);
            polys.push(value);
        }
    }

    Ok(Sampled::new(
        NttMatrix::from_polys(parameter_set.core.k, parameter_set.core.l, polys)?,
        report,
    ))
}

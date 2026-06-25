# M7 long benchmark report

This document reports the M7 benchmark run using the longer Criterion profile
requested after the initial smoke run:

- Criterion `sample_size`: 50
- Criterion `measurement_time`: 3 seconds per benchmark
- Criterion `warm_up_time`: 500 milliseconds per benchmark
- Feature flag: `m7-benchmarks`

The values below are Criterion mean point estimates with 95% confidence
intervals in parentheses. `target/criterion` remains a local artifact; the
source-controlled summary is this document plus `m7-criterion-results.csv`.

## Environment

- Date: 2026-06-24
- CPU: Apple M4 Pro
- Logical CPUs: 12
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Commit: `99b86c0`
- Working tree: dirty with benchmark/report changes
- Flags: `--features m7-benchmarks`

## Commands

```bash
cargo bench --bench sign_verify --features m7-benchmarks -- --noplot
cargo bench --bench sampling --features m7-benchmarks -- --noplot
cargo bench --bench internals --features m7-benchmarks -- --noplot
cargo bench --bench rejection --features m7-benchmarks
cargo bench --bench param_sweep --features m7-benchmarks
```

Verification commands:

```bash
cargo check --benches --features m7-benchmarks
cargo test --all-features
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## KeyGen / Sign / Verify

| Benchmark | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | ---: | ---: | ---: |
| `keygen_from_seed` | 198.29 us (197.38 us-199.26 us) | 365.23 us (362.87 us-367.99 us) | 538.54 us (535.69 us-541.91 us) |
| Deterministic sign | 239.88 us (238.57 us-241.54 us) | 459.05 us (456.13 us-463.01 us) | 1.5464 ms (1.5224 ms-1.5780 ms) |
| Deterministic sign with report | 430.44 us (428.90 us-431.96 us) | 545.53 us (542.48 us-549.37 us) | 719.50 us (716.47 us-722.49 us) |
| Verify | 165.61 us (162.93 us-169.42 us) | 274.49 us (270.13 us-280.89 us) | 454.17 us (452.99 us-455.37 us) |

Interpretation:

- Verification scales smoothly with `k` and `l`, as expected.
- Deterministic signing remains rejection-loop dependent; the separate rejection
  benchmark below is the better source for attempt distribution.
- The `with report` row includes instrumentation bookkeeping and uses a
  separate deterministic key/message stream, so it should be interpreted as an
  instrumentation cost lane, not as the exact same operation plus a small delta.

## NTT

| Benchmark | Estimate |
| --- | ---: |
| Forward NTT | 1.43 us (1.43 us-1.43 us) |
| Inverse NTT | 1.40 us (1.40 us-1.41 us) |
| Pointwise multiply + inverse NTT | 1.51 us (1.51 us-1.51 us) |

The NTT timings are tight under the longer profile and are useful as a local
baseline for future arithmetic changes.

## Sampling

| Benchmark | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | ---: | ---: | ---: |
| `ExpandA` | 91.03 us (90.77 us-91.29 us) | 158.74 us (158.07 us-159.38 us) | 295.37 us (294.48 us-296.23 us) |
| `ExpandS` | 29.34 us (29.12 us-29.64 us) | 75.63 us (75.38 us-75.92 us) | 53.65 us (53.48 us-53.84 us) |
| `ExpandMask` | 16.67 us (16.63 us-16.72 us) | 22.58 us (22.52 us-22.65 us) | 31.79 us (31.59 us-32.12 us) |
| `SampleInBall` | 1.38 us (1.37 us-1.38 us) | 1.82 us (1.81 us-1.82 us) | 2.12 us (2.12 us-2.13 us) |

Interpretation:

- `ExpandA` is the dominant sampler because it fills the full `k x l`
  transform-domain matrix.
- `ExpandS` is not monotonic across all parameter sets because `eta`, `k`, and
  `l` interact: ML-DSA-65 has `eta = 4`, while ML-DSA-87 returns to `eta = 2`.
- `SampleInBall` scales with `tau` and challenge byte length, but it remains
  small compared with matrix expansion and signing.

## Raw FIPS Encoding

| Raw encoding benchmark | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | ---: | ---: | ---: |
| `pk_encode` | 20.72 us (20.66 us-20.79 us) | 30.52 us (30.32 us-30.77 us) | 39.23 us (39.04 us-39.44 us) |
| `pk_decode` | 7.57 us (7.55 us-7.59 us) | 11.26 us (11.22 us-11.31 us) | 14.94 us (14.88 us-15.00 us) |
| `sk_encode` | 39.84 us (39.73 us-39.95 us) | 61.85 us (61.59 us-62.17 us) | 74.76 us (74.47 us-75.06 us) |
| `sk_decode` | 15.59 us (15.45 us-15.78 us) | 23.42 us (23.37 us-23.48 us) | 29.65 us (29.48 us-29.94 us) |
| `sig_encode` | 38.01 us (37.88 us-38.14 us) | 50.77 us (50.58 us-50.98 us) | 69.20 us (68.93 us-69.46 us) |
| `sig_decode` | 13.80 us (13.71 us-13.92 us) | 18.58 us (18.54 us-18.62 us) | 27.05 us (26.39 us-27.86 us) |
| `w1_encode` | 4.90 us (4.83 us-4.98 us) | 4.84 us (4.82 us-4.87 us) | 6.43 us (6.39 us-6.49 us) |

Encoding cost is visible but remains below the dominant algorithmic operations.
Decode is generally cheaper than encode in this implementation.

## PKIX DER

| PKIX DER benchmark | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | ---: | ---: | ---: |
| SPKI encode | 104.73 ns (104.32 ns-105.15 ns) | 115.75 ns (113.42 ns-119.91 ns) | 125.17 ns (124.41 ns-126.27 ns) |
| SPKI decode | 146.84 ns (146.53 ns-147.15 ns) | 150.01 ns (149.67 ns-150.34 ns) | 154.96 ns (154.31 ns-155.63 ns) |
| `OneAsymmetricKey` encode | 337.43 ns (335.84 ns-339.05 ns) | 388.12 ns (385.52 ns-391.29 ns) | 461.93 ns (451.89 ns-475.98 ns) |
| `OneAsymmetricKey` decode + consistency check | 391.32 us (389.25 us-393.66 us) | 717.89 us (714.85 us-721.45 us) | 1.0668 ms (1.0567 ms-1.0805 ms) |

Interpretation:

- Plain SPKI and `OneAsymmetricKey` DER wrapping is effectively negligible.
- `OneAsymmetricKey` decode with consistency check is expensive by design: RFC
  9881 says consistency checking regenerates the expanded key from the seed and
  compares it with the embedded expanded key.

## Rejection Loop

`benches/rejection.rs` is an executable benchmark with 128 deterministic
messages per parameter set. It records aggregate signing reports, not Criterion
latencies.

| Parameter set | Mean attempts | Min | Max | z/r0 rejects | c*t0/hint rejects | Sampling rejections |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 4.39 | 1 | 28 | 432 | 2 | 1795 |
| ML-DSA-65 | 4.70 | 1 | 25 | 473 | 0 | 3100 |
| ML-DSA-87 | 3.56 | 1 | 16 | 328 | 0 | 3757 |

The means are close to the expected order of magnitude from FIPS 204:
ML-DSA-44 around 4.25, ML-DSA-65 around 5.1, and ML-DSA-87 around 3.85.

## Experimental Parameter Sweep

`benches/param_sweep.rs` uses non-standard `ParameterSet::new_experimental`
metadata. These rows are experiments only, not ML-DSA conformance evidence.

| Variant | gamma1 | gamma2 | tau | omega | sig bytes | Mean y norm | Mean challenge weight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44/base-metadata | 131072 | 95232 | 39 | 80 | 2420 | 130953.62 | 39.00 |
| ML-DSA-44/gamma1-half | 65536 | 95232 | 39 | 80 | 2292 | 65478.31 | 39.00 |
| ML-DSA-44/gamma2-wide | 131072 | 190464 | 39 | 80 | 2420 | 130953.62 | 39.00 |
| ML-DSA-44/tau-plus-8 | 131072 | 95232 | 47 | 80 | 2420 | 130953.62 | 47.00 |
| ML-DSA-44/omega-half | 131072 | 95232 | 39 | 40 | 2380 | 130953.62 | 39.00 |

## Caveats

- This is still a local POC benchmark, not a publication-grade performance
  study. Thermal state, background processes, and Criterion baselines can move
  small percentages.
- The console logs include Criterion "change" messages relative to earlier
  local baselines. Those are not regressions against a committed release; the
  tables above are the current long-profile measurements.
- The benchmark feature enables `instrumentation`, `pkix`, and
  `experimental-params` so all M7 lanes run with one flag.

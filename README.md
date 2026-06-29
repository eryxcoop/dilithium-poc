# dilithium-poc

`dilithium-poc` is a Rust proof of concept for implementing, testing, and
measuring ML-DSA according to [FIPS 204][fips-204], with optional PKIX/X.509
transport helpers according to [RFC 9881][rfc-9881] and minimal CMS
`SignedData` helpers according to [RFC 9882][rfc-9882].

Author: Lorenzo Ruiz Diaz

## Security Notice

This repository is **not** production cryptography. It is an auditable and
measurable proof of concept, not a certified FIPS module and not a library that
should be used to protect real data.

ML-DSA implementations need careful treatment of randomness, side channels,
secret zeroization, fault behavior, parser strictness, and external audit. This
repo is useful for learning, conformance work, experiments, benchmarks, and
review, but it does not claim production readiness.

## Scope

Implemented:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
- Pure ML-DSA `KeyGen`, `Sign`, and `Verify` workflows from FIPS 204.
- Raw FIPS 204 public key, private key, and signature encodings.
- Strict signature, key, hint, and sampling validation.
- SHAKE/XOF-based sampling: `ExpandA(ρ)`, `ExpandS(ρ′)`, `ExpandMask(ρ″,κ)`,
  `SampleInBall(c̃)`, `RejNTTPoly`, and `RejBoundedPoly`.
- NTT-domain matrix support for `Â`.
- Optional RFC 9881 PKIX helpers for OIDs, `AlgorithmIdentifier`,
  `SubjectPublicKeyInfo`, `OneAsymmetricKey`, private-key CHOICEs, and
  `keyUsage`.
- Optional RFC 9882 CMS helpers for pure ML-DSA single-signer `SignedData`,
  including signed attributes, detached or encapsulated content, SHA-512 digest
  support, and strict absent-parameter `AlgorithmIdentifier` handling.
- NIST ACVP/CAVP conformance runners outside the ordinary `tests/` directory.
- Criterion benchmarks for key generation, signing, verification, sampling,
  NTT, encoding/decoding, PKIX, rejection behavior, and parameter experiments.
- Educational failure-analysis notes and a `challenges/` area for intentionally
  vulnerable classroom examples.

Out of scope:

- FIPS certification.
- Production deployment.
- HashML-DSA in PKIX/X.509. RFC 9881 targets pure ML-DSA for certificates,
  CRLs, OCSP, certificate issuance, and related PKIX protocols.
- HashML-DSA in CMS. RFC 9882 specifies pure ML-DSA with an empty FIPS context
  string.
- General-purpose CMS/RFC 5652. The CMS code is intentionally a narrow RFC
  9882 profile, not a full CMS stack with certificate path processing,
  multi-signer discovery, CRLs, or arbitrary attribute semantics.
- Treating historical CRYSTALS-Dilithium vectors as byte-for-byte ML-DSA
  conformance evidence unless they are explicitly adapted to FIPS 204.

## Quick Start

Run the default unit tests:

```bash
cargo test
```

Run all features, including PKIX/CMS, instrumentation, and benchmark-only support:

```bash
cargo test --all-features
```

Run ACVP/FIPS 204 conformance checks:

```bash
cargo test acvp --all-features
```

Run RFC 9881-focused PKIX checks:

```bash
cargo test --features pkix rfc9881_
```

Run RFC 9882-focused CMS checks:

```bash
cargo test --features pkix rfc9882_
```

Run linting with all targets and features:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

When working through Codex/RTK in this repository, prefix shell commands with
`rtk`, for example `rtk cargo test --all-features`.

## Basic API Example

```rust
use dilithium_poc::ml_dsa::KeyPair;
use dilithium_poc::params::ML_DSA_44;

let key_pair = KeyPair::generate(ML_DSA_44).unwrap();
let message = b"hello ML-DSA";
let context = b"example";

let signature = key_pair.private_key().sign(message, context).unwrap();
let ok = key_pair.public_key().verify(message, &signature, context);

assert!(ok);
```

The high-level pure ML-DSA API lives in `dilithium_poc::ml_dsa`.

PKIX/RFC 9881 and CMS/RFC 9882 helpers are available with:

```bash
cargo test --features pkix
```

and live in `dilithium_poc::pkix`.

## Cargo Features

| Feature               | Purpose                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `std`                 | Default feature for ordinary host builds.                                                    |
| `pkix`                | Enables RFC 9881 PKIX and RFC 9882 CMS helpers using `der`, `spki`, `pkcs8`, and `sha2`.      |
| `instrumentation`     | Exposes aggregate signing/sampling reports and deterministic test signing helpers.           |
| `experimental-params` | Enables non-standard parameter metadata for controlled experiments.                          |
| `m7-benchmarks`       | Enables benchmark-only paths; includes `experimental-params`, `instrumentation`, and `pkix`. |

The `instrumentation` and `experimental-params` features are for measurement,
tests, and experiments. They should not be exposed as production APIs.

## Project Layout

```text
src/
  ml_dsa/        High-level FIPS 204 KeyGen, Sign, Verify.
  sampling/      XOF readers, rejection sampling, ExpandA/S/Mask, SampleInBall.
  encoding/      Raw FIPS 204 key, signature, hint, bit, and polynomial encoders.
  poly/          Polynomial, vector, matrix, and NTT-domain types.
  params/        FIPS 204 constants and parameter-set metadata.
  pkix/          RFC 9881 PKIX and RFC 9882 CMS helpers behind the pkix feature.

conformance/     NIST ACVP/CAVP and RFC 9881 conformance runners.
benches/         Criterion benchmarks and benchmark reports.
docs/            Local standards, research notes, and failure-analysis material.
challenges/      Separate workspace crate for educational vulnerable examples.
scripts/         Utility scripts for standards text and ACVP fixtures.
```

## Conformance

The conformance suite intentionally lives under `conformance/`, not `tests/`,
so official vector data and PKIX snapshots remain separate from ordinary unit
tests.

Current coverage:

| Suite                   | Scope                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------- |
| `ML-DSA-keyGen-FIPS204` | Key generation from official seeds for ML-DSA-44/65/87.                                 |
| `ML-DSA-sigGen-FIPS204` | Pure external deterministic and randomized signing.                                     |
| `ML-DSA-sigVer-FIPS204` | Pure external verification, including negative cases.                                   |
| RFC 9881 PKIX           | OIDs, absent parameters, SPKI, private-key CHOICEs, `OneAsymmetricKey`, and `keyUsage`. |
| RFC 9882 CMS            | Minimal pure ML-DSA `SignedData`, signed attributes, detached content, and digest policy. |

Run:

```bash
cargo test acvp --all-features
cargo test --features pkix rfc9881_
cargo test --features pkix rfc9882_
```

See `conformance/README.md` for fixture provenance and executed coverage.

## Benchmarks

Benchmarks are Criterion-based and live under `benches/`.

Useful commands:

```bash
cargo bench --bench sign_verify --features m7-benchmarks
cargo bench --bench internals --features m7-benchmarks
cargo bench --bench sampling --features m7-benchmarks
cargo bench --bench rejection --features m7-benchmarks
cargo bench --bench param_sweep --features m7-benchmarks
```

Recorded benchmark artifacts:

- `benches/m7-results.md`: long-profile M7 benchmark report.
- `benches/m7-criterion-results.csv`: Criterion timing data in nanoseconds.
- `benches/signing-repetition-results.md`: signing-loop repetition report.
- `benches/sampling-results.md`: sampling benchmark notes.

## Educational Challenges

The `challenges/` directory is reserved for intentionally vulnerable examples:
nonce reuse, broken samplers, boundary leaks from bad `γ₁ - β` rejection,
low-bit boundary leaks from bad `γ₂ - β` rejection, missing verifier checks,
permissive parsers, and toy parameter failures.

Challenge code lives in a separate workspace member named
`dilithium-poc-challenges`. Harmless scaffolding, including toy algebra and the
shared transcript format, compiles normally. Concrete vulnerable runners must be
enabled explicitly with the `failure-challenges` feature:

```bash
cargo test -p dilithium-poc-challenges
cargo test -p dilithium-poc-challenges --features failure-challenges
cargo run -p dilithium-poc-challenges --example transcript_smoke --features failure-challenges
```

Challenge code must remain outside the conformant `src/` path. Each challenge
should explain:

- the bug,
- the exploit intuition,
- whether it uses toy params or real ML-DSA params,
- what FIPS 204 or RFC 9881 rule prevents the bug,
- whether a transport-layer bug relates to RFC 9881 or RFC 9882,
- how the strict implementation rejects or avoids the failure.

Start with:

- `challenges/README.md`
- `challenges/roadmap.md`
- `docs/ml-dsa-failure-examples-research.md`

## Reference Documents

- `docs/NIST.FIPS.204.pdf`: local copy of FIPS 204.
- `docs/rfc9881.txt`: local copy of RFC 9881.
- `docs/rfc9882.txt`: local copy of RFC 9882.
- `docs/CRYSTALS_Dilithium_Clean.md`: useful historical context, not normative.
- `docs/ml-dsa-failure-examples-research.md`: research notes for educational
  failure challenges.
- `roadmap.md`: milestone plan and implementation history.
- `AGENTS.md`: contributor and agent guidance with normative ML-DSA, PKIX, and
  CMS notes.

Official references:

- [FIPS 204: Module-Lattice-Based Digital Signature Standard][fips-204]
- [RFC 9881: Use of ML-DSA in PKIX][rfc-9881]
- [RFC 9882: Use of ML-DSA in CMS][rfc-9882]

[fips-204]: https://doi.org/10.6028/NIST.FIPS.204
[rfc-9881]: https://datatracker.ietf.org/doc/rfc9881/
[rfc-9882]: https://datatracker.ietf.org/doc/rfc9882/

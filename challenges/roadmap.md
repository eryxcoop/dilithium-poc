# Challenges Roadmap

This roadmap turns the failure-analysis document into implementable classroom
exercises. The order is intentional: start with high-signal failures, then add
parameter experiments, parser/protocol bugs, and finally advanced statistical or
algebraic demos.

## Status Legend

- `planned`: design selected, not implemented.
- `scaffolded`: directory and README exist.
- `demo`: vulnerable path and exploit runner exist.
- `verified`: demo has automated checks and expected output.
- `teaching-ready`: README, exploit, FIPS comparison, and commands are polished.

## Phase 0: Harness and Guardrails

Status: `scaffolded`

Build the shared structure that keeps vulnerable material from leaking into the
conformant crate.

- Use `challenges/` as a separate Cargo workspace member.
- Keep toy parameters in separate educational algebra types under
  `challenges/src/toy/`.
- Use transcript-first runners under `challenges/src/shared/`, with examples for
  class output and tests for deterministic assertions.
- Gate intentionally vulnerable runners behind `failure-challenges`.
- Gate intentionally incomplete student exercises behind `exercises`.
- Add a template README for each challenge.
- Add CI-safe tests that assert vulnerable examples stay outside the FIPS path.
- Document every intentional violation with the exact FIPS 204 or RFC 9881 rule.

Exit criteria:

- Done: a new challenge can be added without touching production signing or
  verifying.
- Done: running normal ACVP/conformance tests does not depend on challenge code.
- Done: vulnerable demos require an explicit `failure-challenges` feature.
- Done: student stubs require an explicit `exercises` feature.
- Done: add `challenges/template.md` for challenges that grow beyond a
  phase-level doc.
- Pending: add the first real vulnerable demo.

## Phase 1: Core Classroom Failures

Status: `demo`

These are the first exercises to implement because they are direct, memorable,
and map cleanly to the strongest security failures.

| Challenge              | Bug                                 | Demo target                             | Impact                                       |
| ---------------------- | ----------------------------------- | --------------------------------------- | -------------------------------------------- |
| `nonce_reuse`          | Reuse the same `y` / `ρ″,κ`         | Real or near-real controlled signatures | Recover `s1` or a signing-equivalent secret  |
| `sampler_patterned_y`  | Patterned mask sampler              | Toy or reduced setting                  | Leak equations while signatures still verify |
| `verifier_no_ctilde`   | Skip `c̃ == H(μ \|\| w1Encode(w1′))` | Toy or real structural signature        | Trivial forgery                              |
| `verifier_no_z_bound`  | Skip `\|\|z\|\|∞ < γ₁ - β`          | Toy params                              | Forgery outside the short-vector domain      |
| `verifier_no_omega`    | Accept dense/malformed `h`          | Toy params plus strict comparison       | Hint-assisted forgery or malleability        |
| `toy_params_too_small` | Shrink `τ`, `λ`, `k`, `l`, or `n`   | Toy params                              | Exhaustive search or linear algebra attack   |

Exit criteria:

- Done: each challenge has an exploit runner exposed by
  `challenges/src/failures/phase1/` and the `phase1` example.
- Done: each challenge has a matching student stub under
  `challenges/src/exercises/phase1/` and a gated exercise test.
- Done: verifier challenges compare vulnerable acceptance against strict FIPS
  rejection conditions where applicable.
- Done: `challenges/phase1.md` explains the role of `ρ″`, `κ`, `μ`, `c̃`,
  `Â`, `∞`, `τ`, `λ`, `γ₁`, `β`, or `ω` as relevant.
- Pending for `teaching-ready`: add expected full command output snapshots once
  the classroom transcript wording stabilizes.

## Phase 2: Parameter-Specific Experiments

Status: `planned`

These examples teach why the constants are coupled. They can be smaller and more
experimental than Phase 1, but should still produce a concrete observable
failure.

| Challenge                   | Parameter focus    | Demo idea                                              |
| --------------------------- | ------------------ | ------------------------------------------------------ |
| `tau_zero_forgery`          | `τ`                | Set `τ = 0`, make `c = 0`, forge by choosing short `z` |
| `lambda_too_short`          | `λ`                | Truncate `c̃` and search for a challenge collision      |
| `eta_too_small`             | `η`                | Use `η = 0/1` and recover secrets by enumeration       |
| `gamma1_edge_leak`          | `γ₁`, `β`          | Collect signatures and measure boundary bias in `z`    |
| `gamma2_hint_pressure`      | `γ₂`, `ω`          | Show excessive carries or overpowered hints            |
| `small_ring_linear_algebra` | `n`, `k`, `l`, `q` | Recover toy secrets with linear algebra                |

Exit criteria:

- Every experiment states clearly whether it is toy-only or meaningful for real
  parameter sets.
- Parameter changes are not exposed through normal public APIs.
- Results are reproducible with deterministic seeds.

## Phase 3: Parsing, Encoding, and Protocol Boundaries

Status: `planned`

These are less algebraic but very realistic implementation pitfalls.

| Challenge                       | Broken rule                    | Demo idea                                                   |
| ------------------------------- | ------------------------------ | ----------------------------------------------------------- |
| `trailing_bytes`                | Accept exact-size violations   | Accept `sig \|\| garbage` in vulnerable parser              |
| `ctx_replay`                    | Omit `ctx` from `M′`           | Replay one signature across `"login"` and `"firmware"`      |
| `hint_malleability`             | Accept non-canonical hints     | Accept duplicate, unsorted, or over-`ω` hints               |
| `pkix_null_parameters`          | Accept DER `NULL` parameters   | Contrast vulnerable PKIX parser with RFC 9881 strict parser |
| `spki_wrong_bitstring`          | Accept non-octet-aligned SPKI  | Show malformed public key wrapper acceptance                |
| `private_key_both_inconsistent` | Skip seed/expanded consistency | Accept mismatched RFC 9881 `both` private key               |

Exit criteria:

- Vulnerable parser behavior is isolated from `src/encoding` and `src/pkix`.
- Each demo has a strict-vs-vulnerable comparison.
- PKIX examples cite RFC 9881 and use absent `parameters` as the conformant
  baseline.

## Phase 4: Advanced Structure and Statistical Demos

Status: `planned`

These are better for a second class or workshop because they need more math,
more samples, or more explanation.

| Challenge                       | Focus          | Demo idea                                                       |
| ------------------------------- | -------------- | --------------------------------------------------------------- |
| `expand_a_repeated_columns`     | `ρ`, `Â`       | Drop row/column index binding and exploit repeated columns      |
| `rho_prime_reuse`               | `ρ′`           | Reuse secret expansion across keys and compare public equations |
| `wrong_zeta_rank_loss`          | `ζ`            | Use a degenerate NTT root in toy params and observe collisions  |
| `small_or_composite_q`          | `q`            | Make ring arithmetic enumerable or non-field-like               |
| `d_too_large_no_ct0_check`      | `d`, `γ₂`      | Over-compress `t1` and skip `\|\|c t0\|\|∞ < γ₂`                |
| `biased_rejection_distribution` | `γ₁`, `β`, `η` | Use accepted/rejected edge statistics to leak secret signs      |

Exit criteria:

- Each advanced demo includes a short derivation or notebook-style explanation.
- Long-running statistical demos record sample count and expected runtime.
- The README warns when a demo is intuition-only for toy params.

## Documentation Tasks

Status: `planned`

- Add `challenges/template.md` once the first challenge shape is settled.
- Add a top-level map from each challenge to the corresponding section in
  `docs/ml-dsa-failure-examples-research.md`.
- Add a "how to teach this" note per challenge: 5-minute version, 20-minute
  version, and optional homework.
- Add expected command outputs for completed demos.
- Add a glossary for `ρ`, `ρ′`, `ρ″`, `μ`, `c̃`, `Â`, `∞`, `η`, `τ`, `λ`,
  `γ₁`, `γ₂`, `β`, `ω`, `κ`.

## Verification Tasks

Status: `planned`

For every implemented challenge:

- The vulnerable runner must fail closed if prerequisites are missing.
- The exploit must be deterministic under fixed seeds.
- The conformant implementation must still pass:

```bash
cargo test acvp --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

- If a challenge uses benchmarks or many samples, record the profile and results
  under `challenges/<challenge-name>/results.md`.

## Resolved Design Decisions

- `challenges/` is a separate Cargo workspace member named
  `dilithium-poc-challenges`.
- Toy algebra is separate from production `Poly`/`PolyVector` and lives under
  `challenges/src/toy/`.
- Runners should produce classroom-friendly transcripts and deterministic tests.
  The shared transcript format lives under `challenges/src/shared/`.
- Intentionally vulnerable runners require the explicit feature
  `failure-challenges`.

## Open Design Decisions

- Whether future toy algebra needs matrices and linear solvers in this crate, or
  whether individual challenges should implement only the algebra they need.
- Whether challenge runners should eventually share one CLI dispatcher or remain
  as separate `cargo run --example ...` entry points.

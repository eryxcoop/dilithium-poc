# ML-DSA Failure Challenges

This directory is the educational lab for "what can go wrong" examples around
ML-DSA. It is intentionally outside `src/` so the conformant implementation
remains clean, auditable, and aligned with FIPS 204 and RFC 9881.

Every challenge in this directory must be treated as non-production,
non-FIPS-conformant code. The point is to make a single security failure visible
and teachable, not to offer alternate ML-DSA APIs.

## Goals

- Show how small-looking changes can break ML-DSA's security argument.
- Keep each failure isolated: one bug, one exploit idea, one lesson.
- Reuse safe crate components when helpful, but never modify the conformant
  `src/` path to make a vulnerable example work.
- Prefer tiny deterministic demos that can run in class without special setup.
- Use Unicode notation in explanations: `ρ`, `ρ′`, `ρ″`, `μ`, `c̃`, `Â`, `∞`,
  `η`, `τ`, `λ`, `γ₁`, `γ₂`, `β`, `ω`, `κ`.

## Safety Boundary

Challenge code may intentionally violate FIPS 204, but only inside this
directory or behind a clearly named feature/test boundary. A valid challenge
must never make the main `keygen`, `sign`, `verify`, sampling, encoding, PKIX,
or ACVP paths more permissive.

Use these labels consistently:

- `FIPS path`: the real implementation under `src/`.
- `vulnerable path`: the intentionally broken implementation in `challenges/`.
- `toy params`: reduced parameters used only to make the exploit fast.
- `real params`: one of ML-DSA-44, ML-DSA-65, or ML-DSA-87.

## Design Decisions

The challenge lab uses four guardrails:

- `challenges/` is a separate Cargo workspace member. It depends on the main
  crate by path, but the main crate does not depend on it.
- Toy algebra uses separate educational types under `challenges/src/toy/`.
  Reduced `n`, altered `q`, and other toy parameters must not be represented as
  FIPS-compatible `Poly`, `PolyVector`, or `ParameterSet` values.
- Runners should emit a classroom transcript and have deterministic tests. The
  shared format lives under `challenges/src/shared/`.
- Intentionally vulnerable runners must be gated by the `failure-challenges`
  feature. Normal workspace builds compile the harmless harness, not vulnerable
  demos.
- Student exercise stubs are gated by the separate `exercises` feature. Those
  tests are expected to fail until a student completes the missing functions.

## Closed Catalog

The active challenge set is closed. This is the complete classroom catalog:

| Challenge | Lesson |
| --- | --- |
| `nonce_reuse` | Reusing `y` / `ρ″,κ` cancels the mask and recovers a toy `s₁`. |
| `sampler_patterned_y` | A position-biased mask sampler leaks `s₁` statistically. |
| `eta_unbounded_secret` | Secrets outside `[-η, η]` become visible through averaged responses. |
| `gamma1_beta_boundary_oracle` | Accepting the forbidden `γ₁ - β ≤ |z_j| < γ₁` band leaks `s₁`. |
| `gamma2_lowbits_boundary_oracle` | Accepting low-bit edge values near `γ₂` leaks `s₂`. |
| `gamma2_lowbits_pruned_recovery` | Larger low-bit edge recovery forces interval pruning over brute force. |
| `verifier_no_ctilde` | Skipping `c̃ == H(μ || w1Encode(w₁′))` enables forgery. |
| `lambda_too_short_cross_message` | Checking only 24 bits of `c̃` enables cross-message forgery. |
| `toy_dense_hint_forgery` | Accepting hint weight beyond `ω` enables toy signature forgery. |
| `toy_params_too_small` | Tiny toy parameters make exhaustive recovery visible. |

This list is the source of truth for `challenges/src/failures/`,
`challenges/src/exercises/`, `challenges/tests/`, and [`classroom.md`](classroom.md).
Do not add new challenge families from old notes or brainstorming unless the
catalog is deliberately reopened and all catalog surfaces are updated together.

## Challenge Shape

Lightweight challenge docs can live in a catalog-level file such as
[`classroom.md`](classroom.md). A challenge should get its own directory only when it
has fixtures, expected-output snapshots, custom runners, or result artifacts.

When a challenge grows beyond the phase-level doc, use this structure:

```text
challenges/<challenge-name>/
  README.md
  src-or-runner files
  fixtures or expected-output files, if needed
```

The per-challenge `README.md` should include:

- Objective: what the student is trying to recover, forge, or distinguish.
- Bug: the exact FIPS 204 or RFC 9881 rule being violated.
- Setup: whether the demo uses toy params or real params.
- Hint: the mathematical handle, for example `z - z′ = (c - c′)s1`.
- Expected result: what success looks like.
- FIPS defense: why the conformant implementation rejects or avoids it.

## Commands

Compile and test the harmless challenge harness:

```bash
cargo test -p dilithium-poc-challenges
```

Compile the intentionally vulnerable runner surface explicitly:

```bash
cargo test -p dilithium-poc-challenges --features failure-challenges
cargo run -p dilithium-poc-challenges --example transcript_smoke --features failure-challenges
cargo run -p dilithium-poc-challenges --example classroom --features failure-challenges
```

Run the student exercise surface:

```bash
cargo test -p dilithium-poc-challenges --features exercises --test exercises_failures
```

Those tests intentionally hit `todo!()` in a fresh checkout.

The current classroom demos are implemented as deterministic transcript runners
under `challenges/src/failures/`. They are intentionally small and
classroom-oriented: some use toy algebra, while verifier failures use
strict-vs-vulnerable structural comparisons. The teaching notes live in
[`classroom.md`](classroom.md). Student-facing stubs live under
`challenges/src/exercises/` and are enabled only with the `exercises` feature.

## References

- Research notes: `docs/ml-dsa-failure-examples-research.md`.
- Normative ML-DSA reference: `docs/NIST.FIPS.204.pdf`.
- Normative PKIX/X.509 reference: `docs/rfc9881.txt`.
- Repo guidance: `AGENTS.md`.

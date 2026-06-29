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
  feature. Normal workspace builds compile the harmless harness, not the future
  vulnerable demos.
- Student exercise stubs are gated by the separate `exercises` feature. Those
  tests are expected to fail until a student completes the missing functions.

## Challenge Shape

Lightweight challenge docs can live in a phase-level file such as
[`phase1.md`](phase1.md). A challenge should get its own directory only when it
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
cargo run -p dilithium-poc-challenges --example phase1 --features failure-challenges
```

Run the Phase 1 student exercises:

```bash
cargo test -p dilithium-poc-challenges --features exercises --test exercises_phase1
```

Those tests intentionally hit `todo!()` in a fresh checkout.

## First Track

The first implementation track should prioritize the strongest classroom demos:

1. `nonce_reuse`: force the same `y` / `ρ″,κ` in two signatures and recover
   `s1` or a signing-equivalent secret in a controlled setting.
2. `sampler_patterned_y`: sample `y` with a position-dependent mean bias and
   show how many signatures can leak `s1` statistically.
3. `eta_unbounded_secret`: let `s1` escape the `|η|` bound and recover it from
   averages of `z = y + c·s1`.
4. `verifier_no_ctilde`: remove `c̃ == H(μ || w1Encode(w1′))` and demonstrate
   a trivial forgery.
5. `toy_dense_hint_forgery`: in toy params, use overweight hints to forge a
   message without the private key while replay to another message still fails.
6. `toy_params_too_small`: reduce `τ`, `λ`, `k`, `l`, or `n` until exhaustive
   search or linear algebra becomes visible.

The Phase 1 demos are implemented as deterministic transcript runners under
`challenges/src/failures/phase1/`. They are intentionally small and
classroom-oriented: some use toy algebra, while verifier failures use
strict-vs-vulnerable structural comparisons. The teaching notes live in
[`phase1.md`](phase1.md). Student-facing stubs live under
`challenges/src/exercises/phase1/` and are enabled only with the `exercises`
feature.

## Extended Track

After the first track, add examples that are subtler but closer to real
implementation mistakes:

- `lambda_too_short`: truncate `c̃` and find collisions or preimages in a toy
  setting.
- `tau_zero_forgery`: set `τ = 0` and forge because `SampleInBall(c̃)` always
  gives `c = 0`.
- `eta_too_small`: use `η = 0` or `η = 1` and recover secrets by enumeration in
  toy params.
- `expand_a_repeated_columns`: derive `Â` with missing row/column binding and
  exploit repeated structure.
- `gamma1_edge_leak`: use a too-small `γ₁` or wrong `β` and measure boundary
  bias in `z = y + c s1`.
- `trailing_bytes`: accept `sig || garbage` in a permissive parser and compare
  against strict FIPS decoding.
- `ctx_replay`: omit `ctx` from `M′` and replay a signature across domains.
- `pkix_null_parameters`: accept DER `NULL` in `AlgorithmIdentifier.parameters`
  and contrast it with RFC 9881's absent-parameters rule.

## References

- Research notes: `docs/ml-dsa-failure-examples-research.md`.
- Normative ML-DSA reference: `docs/NIST.FIPS.204.pdf`.
- Normative PKIX/X.509 reference: `docs/rfc9881.txt`.
- Repo guidance: `AGENTS.md`.

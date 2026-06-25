# Phase 1: Core Classroom Failures

These demos are deterministic transcript runners exposed through:

```bash
cargo run -p dilithium-poc-challenges --example phase1 --features failure-challenges
```

They are intentionally small. The current shape keeps documentation in one file
while the demos live under `challenges/src/failures/phase1/`. A challenge
should get its own directory only when it has fixtures, expected-output
snapshots, custom runners, or result artifacts.

Student-facing stubs live under `challenges/src/exercises/phase1/` and are
gated by the `exercises` feature:

```bash
cargo test -p dilithium-poc-challenges --features exercises --test exercises_phase1
```

Those tests are expected to fail until the exercise functions are completed.

## nonce_reuse

### Objective

Recover a toy `s₁` value from two signatures that reuse the same mask `y`.

### Bug

The vulnerable signer reuses the same `y` / `ρ″,κ` domain for two signatures.

### Setup

Toy params: scalar arithmetic modulo a small prime `q = 97`.

### Hint

Two responses have the form `z₁ = y + c₁s₁` and `z₂ = y + c₂s₁`, so
`z₂ - z₁ = (c₂ - c₁)s₁`.

### Expected Result

The transcript recovers the original toy `s₁` exactly.

### FIPS Defense

ML-DSA derives masks from `ρ″` and `κ`; rejected attempts advance `κ`, and new
signatures derive fresh domains so accepted signatures do not reuse `y`.

## sampler_patterned_y

### Objective

Show that a patterned mask sampler can leak equations about `s₁` even when the
response shape still looks like `z = y + c·s₁`.

### Bug

The vulnerable signer replaces FIPS `ExpandMask(ρ″, κ)` with a repeated
coefficient pattern.

### Setup

Toy params: a four-coefficient polynomial over a small ring.

### Hint

If `y` is visibly patterned and `c = 1`, then `z - y = s₁`.

### Expected Result

The transcript recovers the toy secret coefficients from one response.

### FIPS Defense

FIPS 204 prescribes `ExpandMask(ρ″, κ)` and its coefficient distribution; a
patterned sampler violates that signing distribution.

## verifier_no_ctilde

### Objective

Demonstrate that skipping the final `c̃` recomputation check makes structural
forgery trivial.

### Bug

The vulnerable verifier skips `c̃ == H(μ || w1Encode(w₁′))`.

### Setup

Toy structural verifier comparison.

### Hint

Without the Fiat-Shamir binding, an attacker can choose convenient `z`, `h`,
and arbitrary `c̃`.

### Expected Result

The vulnerable path accepts while the strict comparison rejects.

### FIPS Defense

ML-DSA recomputes `c̃′ = H(μ || w1Encode(w₁′), λ/4)` and accepts only if
`c̃′ == c̃`.

## verifier_no_z_bound

### Objective

Show that accepting oversized `z` values leaves the intended short-vector
domain.

### Bug

The vulnerable verifier skips `||z||∞ < γ₁ - β`.

### Setup

Toy params with an intentionally small bound.

### Hint

Choose a response whose equation might otherwise be accepted but whose `∞` norm
is visibly larger than `γ₁ - β`.

### Expected Result

The vulnerable path accepts while the strict bound check rejects.

### FIPS Defense

ML-DSA accepts only if `||z||∞ < γ₁ - β`, preserving the short-response
condition needed by the security argument.

## verifier_no_omega

### Objective

Show why hint vectors `h` are adversarial input and must be bounded and
canonical.

### Bug

The vulnerable verifier accepts hint vectors with weight greater than `ω`.

### Setup

Toy structural verifier comparison.

### Hint

Dense hints give the attacker too much control over `UseHint(h, w′)`.

### Expected Result

The transcript shows a hint weight above toy `ω` accepted only by the vulnerable
path.

### FIPS Defense

FIPS signature decoding and hint use reject malformed or over-`ω` hints.

## toy_params_too_small

### Objective

Recover a toy secret by exhaustive search after shrinking the algebraic
parameter space.

### Bug

The vulnerable setup shrinks `n`, `k`, `l`, `q`, and the search space outside
FIPS 204 parameter sets.

### Setup

Toy params: `n = k = l = 1` and `q = 17`.

### Hint

In the toy equation `t = a·s₁`, every candidate `s₁` can be tried directly.

### Expected Result

The transcript recovers `s₁` by trying all `q` candidates.

### FIPS Defense

ML-DSA uses large coupled parameters, including `τ`, `λ`, `γ₁`, `β`, and `ω`,
so this classroom search does not model a feasible attack on FIPS sets.

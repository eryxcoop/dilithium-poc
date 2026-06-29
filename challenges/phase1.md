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

Show that a statistically biased mask sampler can leak `s₁` over many valid
looking signatures, even when no single signature directly reveals `y`.

### Bug

The vulnerable signer replaces FIPS `ExpandMask(ρ″, κ)` with a sampler whose
mean depends on the coefficient position.

### Setup

Toy stats with the ML-DSA-65 `s₁` shape: `η = 4`, `l = 5`, `n = 256`, so the
secret has 1280 coefficients. The demo first audits the broken sampler by
generating many `y` vectors, then uses many signatures. The hidden distribution
has a position-dependent mean:

```text
even positions: E[yᵢ] = +2
odd positions:  E[yᵢ] = -2
```

### Hint

Condition on positions where `cᵢ = 1`:

```text
E[zᵢ | cᵢ = 1] ≈ E[yᵢ] + s₁ᵢ
```

First estimate `E[yᵢ]` from sampled masks. Then average the observed `zᵢ`,
subtract the inferred bias mean, round, and clamp to `[-η, η]`.

### Expected Result

The transcript recovers all 1280 toy secret coefficients from aggregate
statistics and prints the first eight recovered values.

### FIPS Defense

FIPS 204 prescribes `ExpandMask(ρ″, κ)` and its coefficient distribution; a
position-biased sampler violates that signing distribution and can leak
information statistically.

## verifier_no_ctilde

### Objective

Forge a signature for a chosen message against a verifier that reconstructs the
ML-DSA verification equation but skips the final `c̃` recomputation check.

### Bug

The vulnerable verifier skips `c̃ == H(μ || w1Encode(w₁′))`.

### Setup

Real ML-DSA-44 key material, a target message `M`, and a context `ctx`. The
broken verifier decodes `pk` and `sig`, computes `μ`, samples `c`, reconstructs
`w₁′ = UseHint(h, Âz - c·t₁·2ᵈ)`, and checks the `z` and `ω` bounds, but it
never compares the supplied `c̃` with `H(μ || w1Encode(w₁′), λ/4)`.

### Hint

Without the Fiat-Shamir binding, the reconstructed `w₁′` is computed but never
bound back to the supplied challenge seed. The attacker can choose convenient
bounded `z`, valid `h`, and a target-derived but unauthenticated `c̃`.

### Expected Result

The vulnerable `verify()` path accepts the forged `Signature` for the chosen
message and even accepts the same signature for a different message. The real
`PublicKey::verify` rejects both after recomputing `c̃′`.

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

## toy_dense_hint_forgery

### Objective

Forge a toy signature for a chosen message without knowing the private key,
using only dense hints that a broken verifier accepts.

### Bug

The vulnerable verifier accepts hint vectors with weight greater than `ω`.

### Setup

Toy params with a nontrivial ring: `n = 8`, `q = 97`, `γ₂ = 8`, `ω = 2`, and
`||z||∞ < 3`. The public key consists of one toy polynomial `a` and one public
polynomial `t₁ = a·s` derived from a hidden toy secret `s`. The attacker knows
only `a`, `t₁`, the target message, and the context.

### Hint

Search over bounded `z`, over binary hint vectors `h` with `weight(h) > ω`, and
over toy `c̃` values. For each candidate, reconstruct

```text
w_approx = a·z - c·t₁
```

with `c = SampleChallenge(c̃)`, then apply `UseHint(h, w_approx)` coefficientwise.
Dense hints give enough `±1 mod m` corrections on the high bits to make the
recomputed `c̃' = H(μ || w₁')` land on the same `c̃`.

### Expected Result

The vulnerable path accepts a forged toy signature for the target message even
though the search used no private key material. The strict verifier rejects the
same forgery because `weight(h) > ω`, and replaying it on another message still
fails because `c̃` remains bound to `μ`.

### FIPS Defense

Sparse hints are part of the ML-DSA signature language. A verifier must reject
over-`ω` hints before `UseHint` consumes attacker-controlled corrections.

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

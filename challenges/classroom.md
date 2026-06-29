# Classroom Failures

These demos are deterministic transcript runners exposed through:

```bash
cargo run -p dilithium-poc-challenges --example classroom --features failure-challenges
```

They are intentionally small. The current shape keeps documentation in one file
while the demos live under `challenges/src/failures/`. A challenge
should get its own directory only when it has fixtures, expected-output
snapshots, custom runners, or result artifacts.

Student-facing stubs live under `challenges/src/exercises/` and are
gated by the `exercises` feature:

```bash
cargo test -p dilithium-poc-challenges --features exercises --test exercises_failures
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

## eta_unbounded_secret

### Objective

Recover a wide toy `s₁` from valid-looking signatures when the implementation
forgets to keep secret coefficients inside the `|η|` bound.

### Bug

The vulnerable signer samples or accepts `s₁` coefficients outside `[-η, η]`.

### Setup

Toy stats with a less tiny secret shape: `l = 5`, `n = 128`, so `s₁` has 640
coefficients. The nominal ML-DSA-style bound is `η = 2`, but the broken path
samples secrets in `[-24, 24]`. Each observed coefficient uses

```text
zᵢ = yᵢ + cᵢ·s₁ᵢ
```

with centered mask noise `yᵢ ∈ [-4,4]` and toy challenge coordinates
`cᵢ ∈ {-1, 0, 1}`.

### Hint

Condition separately on `cᵢ = 1` and `cᵢ = -1`:

```text
E[zᵢ | cᵢ = 1]  ≈  s₁ᵢ
E[zᵢ | cᵢ = -1] ≈ -s₁ᵢ
```

so

```text
(E[zᵢ | cᵢ = 1] - E[zᵢ | cᵢ = -1]) / 2 ≈ s₁ᵢ
```

When `s₁` is much wider than the mask, `c·s₁` dominates the noise and the
secret becomes visible by averaging many signatures.

### Expected Result

The transcript uses 512 signatures to recover all 640 toy secret coefficients
exactly.

### FIPS Defense

`ExpandS` and secret-key decoding must keep `s₁` and `s₂` inside `[-η, η]`;
otherwise `z` stops hiding the secret statistically.

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

## lambda_too_short_cross_message

### Objective

Forge a toy signature for an unsigned target message by colliding only the
first 24 bits of `c̃` with a legitimately signed transcript for another
message.

### Bug

The vulnerable verifier truncates `c̃` below the `λ`-sized challenge length and
checks only the first 24 bits.

### Setup

Toy params with a public polynomial `a`, a hidden secret `s`, and
`t = a·s mod (x^n + 1)`. The signer legitimately signs one message `M_A` by
sampling bounded masks `y`, while the attacker searches bounded responses `z`
for a different message `M_B`. Both sides hash

```text
c̃_full = H_full(μ || w₁)
```

but the broken verifier compares only `prefix24(c̃_full)`.

### Hint

Look for a pair of transcripts with

```text
prefix24(H_full(μ_A || w₁^(A))) = prefix24(H_full(μ_B || w₁^(B)))
```

while the full 32-bit values still differ. Reuse the signed message's full
`c̃` on the unsigned message. The vulnerable verifier derives the same scalar
challenge from that reused seed and accepts because only the first 24 bits are
checked.

### Expected Result

The transcript shows a strict-valid signature on `M_A`, then a forged
signature for unsigned `M_B` that the truncated verifier accepts and the strict
verifier rejects.

### FIPS Defense

`λ` is the entropy budget for Fiat-Shamir. Truncating `c̃` makes cross-message
collisions searchable and can turn transcript collisions into forgeries.

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

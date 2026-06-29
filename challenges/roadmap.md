# Challenges Catalog

This document is no longer a backlog. It records the closed classroom challenge
set for `dilithium-poc-challenges`.

The catalog is complete as-is. Historical brainstorming notes, research notes,
and old roadmap ideas are not active work items. Do not add a new challenge
unless the catalog is deliberately reopened and the following surfaces are
updated together:

- `challenges/src/failures/`
- `challenges/src/exercises/`
- `challenges/tests/`
- `challenges/classroom.md`
- `challenges/README.md`
- `AGENTS.md`

## Closed Set

| Challenge | Broken rule | Teaching target |
| --- | --- | --- |
| `nonce_reuse` | Reuse the same `y` / `ρ″,κ` across signatures | Algebraic recovery of a toy `s₁` |
| `sampler_patterned_y` | Use a position-biased mask sampler | Statistical recovery of `s₁` from biased masks |
| `eta_unbounded_secret` | Let secret coefficients escape `[-η, η]` | Wide secrets leak through averaged `z` values |
| `gamma1_beta_boundary_oracle` | Check `∥z∥∞ < γ₁` instead of `γ₁ - β` | Boundary-oracle recovery of `s₁` |
| `gamma2_lowbits_boundary_oracle` | Check `∥r₀∥∞ < γ₂` instead of `γ₂ - β` | Low-bits boundary-oracle recovery of `s₂` |
| `verifier_no_ctilde` | Skip `c̃ == H(μ || w1Encode(w₁′))` | Structural forgery when Fiat-Shamir binding is missing |
| `lambda_too_short_cross_message` | Check only 24 bits of `c̃` | Cross-message forgery from short challenge output |
| `toy_dense_hint_forgery` | Accept hint weight beyond `ω` | Toy forgery using overpowered hints |
| `toy_params_too_small` | Shrink toy parameters until search is feasible | Exhaustive recovery in a tiny public equation |

## Ordering

The classroom order is intentional:

1. `nonce_reuse`
2. `sampler_patterned_y`
3. `eta_unbounded_secret`
4. `gamma1_beta_boundary_oracle`
5. `gamma2_lowbits_boundary_oracle`
6. `verifier_no_ctilde`
7. `lambda_too_short_cross_message`
8. `toy_dense_hint_forgery`
9. `toy_params_too_small`

That order starts with direct algebra, moves through statistical leaks and
boundary-oracle reasoning, then finishes with verifier/Fiat-Shamir failures and
toy parameter collapse.

## Completion Criteria

For each catalog entry:

- The solved demo lives under `challenges/src/failures/`.
- The student-facing stub lives under `challenges/src/exercises/`.
- The challenge appears in `challenges/tests/failures.rs`.
- The exercise appears in `challenges/tests/exercises_failures.rs`.
- The teaching writeup lives in `challenges/classroom.md`.
- Vulnerable runners require the explicit `failure-challenges` feature.
- Student stubs require the explicit `exercises` feature.

## Verification

The closed catalog is considered healthy when these pass:

```bash
cargo test -p dilithium-poc-challenges
cargo test -p dilithium-poc-challenges --features failure-challenges
cargo test -p dilithium-poc-challenges --features exercises --test exercises_failures --no-run
cargo clippy -p dilithium-poc-challenges --all-targets --all-features -- -D warnings
cargo doc -p dilithium-poc-challenges --features exercises --no-deps
```

The full `exercises_failures` test target is expected to fail in a fresh
checkout because exercise functions intentionally contain `todo!()` for
students.

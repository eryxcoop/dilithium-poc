# ML-DSA conformance vectors

This folder contains the measurable M5/M6 conformance suite. It intentionally
lives outside `tests/` so official vector data and PKIX snapshots are separated
from ordinary unit tests.

## Source

The JSON fixtures under `conformance/acvp/` are copied from the NIST CAVP ACVP
repository:

<https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>

The local ACVP runner validates the FIPS 204 pure ML-DSA external interface
exposed by this crate. The PKIX runner validates RFC 9881 DER transport rules
implemented behind the `pkix` feature.

## Executed Coverage

| ACVP suite              | Scope                                                            | Cases | Status |
| ----------------------- | ---------------------------------------------------------------- | ----: | ------ |
| `ML-DSA-keyGen-FIPS204` | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` key generation from `seed` |    75 | pass   |
| `ML-DSA-sigGen-FIPS204` | pure external deterministic and randomized signing               |    90 | pass   |
| `ML-DSA-sigVer-FIPS204` | pure external signature verification, including negative cases   |    45 | pass   |
| RFC 9881 PKIX           | OIDs, absent parameters, SPKI, private-key CHOICEs, KeyUsage     |     9 | pass   |

## Explicit Non-Scope

The ACVP files also contain groups for pre-hash and/or internal interfaces.
Those groups are parsed but filtered out by the runner because this POC's
current public target is pure external ML-DSA. RFC 9881 PKIX/DER conformance is
measured separately from these raw FIPS 204 algorithm vectors and does not
attempt full X.509 certificate parsing.

## Command

```bash
cargo test acvp --all-features
```

For PKIX/RFC 9881 only:

```bash
cargo test --features pkix rfc9881_
```

The full crate check is:

```bash
cargo test --all-features
```

# dilithium-poc

POC en Rust para implementar y medir ML-DSA segun FIPS 204, con soporte de codificacion PKIX/X.509 segun RFC 9881.

Autor: Lorenzo Ruiz Díaz

## Objetivo

El objetivo de este repositorio es construir una implementacion auditable y medible de ML-DSA, no una libreria criptografica lista para produccion. La POC debe poder demostrar que coincide con el resultado estandar mediante tamanos exactos, vectores de prueba, rechazo de entradas malformadas, OIDs correctos y benchmarks reproducibles.

FIPS 204 define el algoritmo ML-DSA. RFC 9881 define como transportar ML-DSA en certificados X.509 y estructuras PKIX.

## Estado

Estado actual: M0 completo como base del crate.

Ya existe documentacion de trabajo:

- `roadmap.md`: milestones, estructura propuesta del crate, dependencias y plan de benchmarks.
- `AGENTS.md`: notas normativas para futuros agentes o colaboradores.
- `docs/NIST.FIPS.204.pdf`: copia local de FIPS 204.
- `docs/rfc9881.txt`: copia local de RFC 9881.
- `docs/CRYSTALS_Dilithium_Clean.md`: contexto tecnico no normativo sobre Dilithium/ML-DSA.
- `scripts/extract-fips204-text.sh`: genera `tmp/fips204.txt` desde el PDF local usando `pdftotext`.

## Alcance

Incluido:

- ML-DSA-44, ML-DSA-65 y ML-DSA-87.
- KeyGen, Sign y Verify conforme a FIPS 204.
- Codificacion cruda de claves y firmas conforme a FIPS 204.
- OIDs, `AlgorithmIdentifier`, `SubjectPublicKeyInfo` y private key formats conforme a RFC 9881.
- Benchmarks de keygen, signing, verification, sampling, NTT y serializacion.
- Experimentos controlados para evaluar hipotesis sobre parametros FIPS.

Fuera del alcance principal:

- Certificacion FIPS.
- Uso productivo sin auditoria criptografica externa.
- HashML-DSA en PKIX/X.509. RFC 9881 no lo permite para certificados, CRLs, OCSP, emision de certificados y protocolos relacionados.

## Fuentes normativas

- [FIPS 204, Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)
- [RFC 9881, Algorithm Identifiers for ML-DSA in PKIX](https://datatracker.ietf.org/doc/rfc9881/)

Para extraer texto del PDF local:

```sh
scripts/extract-fips204-text.sh
```

## Estructura esperada

La estructura final esta detallada en `roadmap.md`. A grandes rasgos:

```text
src/
  params/
    mod.rs
    constants.rs
    core.rs
    ids.rs
    sets.rs
    sizes.rs
  poly/
    mod.rs
    coeffs.rs
    ntt/
      mod.rs
      domain.rs
      tables.rs
      transform.rs
    polynomial.rs
    vector.rs
    matrix.rs
    validation.rs
  encoding/
  sample.rs
  keygen.rs
  sign.rs
  verify.rs
  pkix/
  types/
tests/
benches/
```

## Uso

Comandos base del M0:

```sh
cargo test
cargo bench
cargo test --all-features
```

El crate expone por ahora features, tipos y metadata normativa; KeyGen/Sign/Verify se implementan en milestones posteriores.

## Criterio de exito

La POC se considera alineada con el estandar cuando:

- Los tamanos de claves y firmas coinciden con FIPS 204.
- KeyGen/Sign/Verify pasan vectores oficiales o equivalentes reproducibles.
- Las firmas alteradas o mal codificadas fallan.
- RFC 9881 usa los OIDs correctos y `AlgorithmIdentifier` sin parametros.
- `SubjectPublicKeyInfo` contiene la public key cruda FIPS en BIT STRING.
- Los private keys seed, expandedKey y both se codifican y validan correctamente.
- Los benchmarks reportan resultados reproducibles para los tres parameter sets.

## Nota de seguridad

Esta POC no debe usarse para proteger datos reales. ML-DSA requiere mucho cuidado con side channels, randomness, borrado de secretos, codificaciones estrictas y validacion de entradas no confiables.

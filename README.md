# dilithium-poc

POC en Rust para implementar y medir ML-DSA segun FIPS 204, con soporte de codificacion PKIX/X.509 segun RFC 9881.

Autor: Lorenzo Ruiz Díaz

## Objetivo

El objetivo de este repositorio es construir una implementacion auditable y medible de ML-DSA, no una libreria criptografica lista para produccion. La POC debe poder demostrar que coincide con el resultado estandar mediante tamanos exactos, vectores de prueba, rechazo de entradas malformadas, OIDs correctos y benchmarks reproducibles.

FIPS 204 define el algoritmo ML-DSA. RFC 9881 define como transportar ML-DSA en certificados X.509 y estructuras PKIX.

## Estado

Estado actual: M7 completo para conformidad FIPS 204 pure ML-DSA, wrappers
PKIX/DER de RFC 9881. La suite `conformance/` valida vectores oficiales NIST
CAVP/ACVP para KeyGen/Sign/Verify y snapshots/negativos PKIX para OIDs,
`AlgorithmIdentifier`, `SubjectPublicKeyInfo`, `OneAsymmetricKey` y KeyUsage.
Los benchmarks M7 viven bajo la feature `m7-benchmarks`.

Ya existe documentacion de trabajo:

- `roadmap.md`: milestones, estructura propuesta del crate, dependencias y plan de benchmarks.
- `AGENTS.md`: notas normativas para futuros agentes o colaboradores.
- `docs/NIST.FIPS.204.pdf`: copia local de FIPS 204.
- `docs/rfc9881.txt`: copia local de RFC 9881.
- `docs/CRYSTALS_Dilithium_Clean.md`: contexto tecnico no normativo sobre Dilithium/ML-DSA.
- `scripts/extract-fips204-text.sh`: genera `tmp/fips204.txt` desde el PDF local usando `pdftotext`.
- `conformance/`: vectores oficiales ACVP y runner de conformidad para
  `keyGen`, `sigGen`, `sigVer` y reglas PKIX/RFC 9881.
- `benches/m7-results.md`: reporte largo reproducible de benchmarks M7.
- `benches/m7-criterion-results.csv`: datos Criterion M7 en nanosegundos.

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

## Uso

Comandos base del M0:

```sh
cargo test
cargo bench
cargo test --all-features
cargo bench --bench sign_verify --features m7-benchmarks
```

La API pure ML-DSA vive en `dilithium_poc::ml_dsa`.
La API PKIX/RFC 9881 vive detras de `--features pkix` en
`dilithium_poc::pkix`.

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

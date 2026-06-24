# Roadmap POC ML-DSA FIPS 204 / RFC 9881 en Rust

## Objetivo

Construir una POC en Rust de ML-DSA conforme a FIPS 204, con empaquetado PKIX/X.509 conforme a RFC 9881. El resultado debe poder medirse contra el estandar: tamanos exactos, vectores de prueba, reglas de codificacion, OIDs, rechazo de entradas malformadas y benchmarks reproducibles.

El alcance principal es la variante pure ML-DSA. RFC 9881 no permite HashML-DSA en certificados X.509 para CRL, OCSP, emision de certificados y protocolos PKIX relacionados; si se experimenta con prehashing, debe quedar fuera del camino RFC 9881 y marcado como no conforme.

## Milestones

### M0 - Base del crate y fuentes normativas

Entregables:

- `Cargo.toml` con un crate de biblioteca y features chicas: `std`, `pkix`, `experimental-params`.
- Modulos vacios o esqueletos con tipos publicos estables para parametros, claves, firmas y errores.
- Copias locales referenciadas desde documentacion:
  - `docs/NIST.FIPS.204.pdf`
  - `docs/rfc9881.txt`
  - `docs/CRYSTALS_Dilithium_Clean.md` como contexto no normativo.
- Script o tarea documentada para regenerar texto desde FIPS:
  - `pdftotext docs/NIST.FIPS.204.pdf /tmp/fips204.txt`

Criterios de salida:

- `cargo test` corre aunque solo existan tests de smoke.
- `cargo bench` o `cargo criterion` queda reservado desde el inicio.
- El README o docs internos aclaran que "Dilithium" historico y "ML-DSA" FIPS no son byte-compatible.

### M1 - Parametros FIPS 204 y tipos de dominio

Entregables:

- `params/` con `ParameterSet`, `CoreParams`, `EncodedSizes` y constantes para `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.
- Tipos internos para polinomios sobre `R_q = Z_q[X]/(X^256 + 1)` y vectores/matrices dimensionados por `(k, l)`.
- Tablas de tamanos esperados:
  - ML-DSA-44: pk 1312, sk 2560, sig 2420.
  - ML-DSA-65: pk 1952, sk 4032, sig 3309.
  - ML-DSA-87: pk 2592, sk 4896, sig 4627.

Criterios de salida:

- Tests que verifiquen tamanos derivados por formula contra FIPS 204.
- Tests que verifiquen `q = 8380417`, `zeta = 1753`, `d = 13`, `(k,l)`, `eta`, `tau`, `lambda`, `gamma1`, `gamma2`, `beta`, `omega`.
- La feature `experimental-params` permite construir parametros alterados solo en tests/benchmarks no conformes.

### M2 - Primitivas aritmeticas y codificacion FIPS

Estado: cerrado para la POC. Quedan implementadas las primitivas aritmeticas,
rounding/hints y codificaciones raw FIPS de claves, firmas y `w1`; `Verify`
solo cubre en este hito la frontera de rechazo por longitudes, y la verificacion
criptografica completa queda para M4.

Entregables:

- Reduccion modular, NTT/inversa, multiplicacion punto a punto en dominio NTT.
- `Power2Round`, `Decompose`, `HighBits`, `LowBits`, `MakeHint`, `UseHint`.
- Codificadores FIPS:
  - `pkEncode` / `pkDecode`
  - `skEncode` / `skDecode`
  - `sigEncode` / `sigDecode`
  - `w1Encode`
  - `HintBitPack` / `HintBitUnpack`

Orden sugerido de implementacion:

1. `coefficient.rs`
   Implementar el tipo `Coefficient`, la normalizacion modulo `q`, representantes canonicos/centrados y operaciones basicas por operator overloading. Antes de tocar NTT o packing, conviene fijar una semantica clara de rangos y representantes mod `q`.
2. `poly/`
   Extender `Poly`, `PolyVector` y `PolyMatrix` con operaciones minimas y chequeos de forma necesarios para las primitivas siguientes, sin entrar todavia en signing o sampling.
3. `poly/ntt/`
   Implementar NTT, inverse NTT y multiplicacion punto a punto en dominio NTT. Primero validar identidad `inv_ntt(ntt(a)) = a` y multiplicacion naive vs NTT para polinomios chicos/controlados.
4. `round.rs`
   Implementar `Power2Round`, `Decompose`, `HighBits` y `LowBits`. Estas funciones son base tanto para compresion de clave publica como para reconstruccion de compromisos en verify.
5. `encoding/bits.rs`
   Implementar primero los bloques de bajo nivel de FIPS:
   `BitsToInteger`, `IntegerToBytes`, `BitsToBytes`, `BytesToBits`, `SimpleBitPack`, `BitPack`, `SimpleBitUnpack`, `BitUnpack`.
6. `encoding/hint.rs`
   Implementar `HintBitPack` y `HintBitUnpack`, junto con tests negativos estrictos. Esta parte merece atencion especial porque FIPS 204 endurece la validacion de hints malformados.
7. `encoding/signature.rs`
   Implementar `w1Encode`, `sigEncode` y `sigDecode`, usando ya los bloques anteriores y asegurando tamanos exactos por parameter set.
8. `encoding/keys.rs`
   Implementar `pkEncode` / `pkDecode` y `skEncode` / `skDecode`. `pkDecode` debe quedar preparado para insumos no confiables; `skDecode` puede seguir tratado como trusted input interno.
9. `round.rs` o modulo dedicado de hints
   Implementar `MakeHint` y `UseHint` despues de tener listas las rutinas de decomposition y el packing de hints. Asi ya se puede testear ida y vuelta entre representacion algebraica y codificacion.
10. Integracion M2
    Cerrar con tests cruzados:
    NTT roundtrip, multiplicacion naive vs NTT, invariantes de rounding, encode/decode roundtrip para pk/sk/sig/hints y casos negativos de decode.

Criterios de salida:

- Tests de ida y vuelta de codificacion para claves, firmas y hints.
- Tests negativos: longitudes incorrectas, hints malformados, firmas con bytes fuera de rango, public keys mal codificadas.
- `Verify` devuelve `false` ante `pk` o `sig` con longitud distinta de la especificada.

### M3 - Sampling y SHAKE

Estado: cerrado para la POC. Quedan implementados SHAKE128/SHAKE256, los
samplers FIPS `RejNTTPoly`, `RejBoundedPoly`, `ExpandA`, `ExpandS`,
`ExpandMask` y `SampleInBall`, junto con limites opcionales tipo Table 3,
tests deterministas y benchmarks de sampling.

Entregables:

- XOF SHAKE128/SHAKE256 segun FIPS 204.
- `RejNTTPoly`, `RejBoundedPoly`, `ExpandA`, `ExpandS`, `ExpandMask`, `SampleInBall`.
- Instrumentacion opcional para contar bytes XOF, rechazos y repeticiones.

Criterios de salida:

- Tests deterministas con seeds fijas.
- Limites opcionales no menores que FIPS 204 Table 3:
  - `ML-DSA.Sign_internal`: 814 iteraciones.
  - `RejBoundedPoly`: 481 iteraciones / 481 bytes XOF.
  - `RejNTTPoly`: 298 iteraciones / 894 bytes XOF.
  - `SampleInBall`: 121 iteraciones / 221 bytes XOF.
- Benchmarks de `ExpandA`, `ExpandS`, `ExpandMask`, `SampleInBall`.

### M4 - KeyGen, Sign, Verify FIPS 204

Estado: cerrado para la POC. Quedan implementados los caminos high-level de
pure ML-DSA: `keygen`, `keygen_from_seed`, signing hedged, signing
deterministico de test/instrumentacion y `verify`, usando las primitivas de
sampling, NTT, rounding, hints y encoding ya cerradas en M2/M3. La
instrumentacion de repeticiones del loop de firma queda registrada por
`SigningReport` y medida localmente en `benches/signing_repetitions.rs`.

Entregables:

- `keygen()` hedged por defecto desde RBG.
- `keygen_from_seed(seed)` solo para KAT/tests y RFC 9881 seed import.
- `sign(sk, msg, ctx)` con `ctx` de maximo 255 bytes.
- `sign_deterministic_for_test(sk, msg, ctx)` usando `rnd = [0; 32]`, expuesto solo para tests o feature explicita.
- `verify(pk, msg, sig, ctx)`.

Criterios de salida:

- Si `ctx.len() > 255`, sign/verify retornan error o fallo segun corresponda.
- Firmas hedged y deterministicas verifican con el mismo `verify`.
- Tests de alteracion de mensaje, firma y public key fallan.
- Instrumentacion de signing registra distribucion de repeticiones, esperando orden de magnitud cercano a FIPS:
  - ML-DSA-44: 4.25.
  - ML-DSA-65: 5.1.
  - ML-DSA-87: 3.85.

### M5 - Conformidad medible

Estado: cerrado para la POC en la frontera FIPS 204 pure external. La suite
`conformance/` usa vectores oficiales NIST CAVP/ACVP descargados desde
`usnistgov/ACVP-Server` y valida `keyGen`, `sigGen` y `sigVer` para
ML-DSA-44/65/87. Los grupos ACVP `preHash` e `internal` quedan fuera del scope
actual porque la POC expone pure ML-DSA; la conformidad DER/PKIX de RFC 9881
permanece en M6.

Entregables:

- Test suite de KATs oficiales o ACVP/CAVP cuando esten disponibles localmente.
- Tests con ejemplos de RFC 9881 para claves publicas, privadas y certificados.
- Snapshot de valores:
  - tamanos crudos FIPS;
  - OIDs RFC;
  - DER de `AlgorithmIdentifier` sin parametros;
  - `SubjectPublicKeyInfo` con raw public key en BIT STRING;
  - `OneAsymmetricKey` con seed, expandedKey y both.

Criterios de salida:

- `cargo test --all-features` valida contra vectores.
- Se reporta una matriz de compatibilidad:
  - FIPS raw key/signature encoding: pass/fail.
  - RFC 9881 public key encoding: pass/fail.
  - RFC 9881 private key formats: pass/fail.
  - RFC 9881 certificate examples: pass/fail.

### M6 - RFC 9881 / PKIX

Entregables:

- Feature `pkix`.
- OIDs:
  - ML-DSA-44: `2.16.840.1.101.3.4.3.17`.
  - ML-DSA-65: `2.16.840.1.101.3.4.3.18`.
  - ML-DSA-87: `2.16.840.1.101.3.4.3.19`.
- `AlgorithmIdentifier` DER donde `parameters` esta ausente.
- `SubjectPublicKeyInfo` que contiene la clave publica cruda FIPS en BIT STRING.
- `OneAsymmetricKey`:
  - seed `[0] OCTET STRING (SIZE 32)`, recomendado;
  - expandedKey `OCTET STRING`;
  - both `SEQUENCE { seed, expandedKey }`.
- Consistency check opcional/por defecto al importar `both`: regenerar expanded key desde seed y comparar byte a byte.

Criterios de salida:

- Rechazar DER que usa `NULL` u otros parametros en `AlgorithmIdentifier`.
- Rechazar `both` inconsistente si se ejecuta el consistency check.
- KeyUsage permitido: al menos uno de `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign`.
- KeyUsage prohibido: `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, `decipherOnly`.

### M7 - Benchmarks y experimentos de parametros

Entregables:

- Benchmarks Criterion:
  - keygen, sign, verify para 44/65/87;
  - NTT e inverse NTT;
  - ExpandA y sampling;
  - encode/decode de pk/sk/sig;
  - DER encode/decode PKIX si `pkix` esta activo.
- `benches/rejection.rs` para medir repeticiones por parametro.
- `benches/param_sweep.rs` bajo `experimental-params`.

Hipotesis a testear:

- Los parametros FIPS producen tamanos exactos y firmas verificables con rechazo esperado razonable.
- Cambios en `gamma1`, `gamma2`, `eta`, `tau` u `omega` afectan mediblemente:
  - tasa de rechazo;
  - distribucion de normas `||z||inf`, `||r0||inf`, `||c t0||inf`;
  - cantidad de hints;
  - tamanos de firmas;
  - fallos de verificacion.
- Los parametros RFC no son parametros criptograficos adicionales: fijan identificadores y codificacion de transporte. Su "correccion" se mide por interoperabilidad DER/PKIX, ausencia de parametros y OIDs correctos.

Criterios de salida:

- `cargo bench --bench sign_verify`
- `cargo bench --bench rejection --features instrumentation`
- Reporte `target/criterion` versionado solo como artefacto local, no como fuente.
- Un resumen reproducible con CPU, Rust version, flags, commit/estado del repo y parametros usados.

### M8 - Hardening minimo de POC

Entregables:

- Cero `unsafe` salvo justificacion explicita.
- Borrado de secretos con `zeroize` si se incorpora como dependencia.
- Separacion de APIs:
  - API publica segura: genera randomness internamente.
  - API deterministic/test: solo test/KAT.
  - API experimental: no conforme.
- Reglas de side-channel documentadas.

Criterios de salida:

- `cargo clippy --all-targets --all-features`
- `cargo test --all-features`
- Auditoria manual de caminos que procesan secretos: signing, private key decode, seed import.

## Estructura propuesta del crate

```text
dilithium-poc/
  Cargo.toml
  AGENTS.md
  roadmap.md
  docs/
    NIST.FIPS.204.pdf
    rfc9881.txt
    rfc9882.txt
    CRYSTALS_Dilithium_Clean.md
  src/
    lib.rs
    coefficient.rs
    error.rs
    params/
      mod.rs
      constants.rs
      core.rs
      ids.rs
      sets.rs
      sizes.rs
    types/
      mod.rs
      private_key.rs
      public_key.rs
      signature.rs
      validation.rs
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
    round.rs
    encoding/
      mod.rs
      bits.rs
      keys.rs
      signature.rs
      hint.rs
    hash.rs
    sample.rs
    keygen.rs
    sign.rs
    verify.rs
    pkix/
      mod.rs
      oid.rs
      spki.rs
      private_key.rs
      certificate.rs
    instrumentation.rs
  tests/
    kat_fips.rs
    rfc9881_pkix.rs
    negative_decode.rs
    tamper.rs
    param_formulas.rs
  benches/
    sign_verify.rs
    internals.rs
    rejection.rs
    param_sweep.rs
  examples/
    keygen_sign_verify.rs
    encode_spki.rs
```

## Dependencias propuestas

Mantener dependencias pocas y justificadas:

- `sha3`: requerido para SHAKE128/SHAKE256. Implementarlo a mano no aporta a la POC.
- `rand_core` y `rand_chacha` en dev/test: RBG inyectable y reproducible para KAT/bench. En produccion preferir `OsRng` o el RBG de la plataforma.
- `criterion` como dev-dependency: benchmarks estadisticos.
- `zeroize`: recomendable para semillas, private keys y temporales sensibles.
- `subtle`: util para comparaciones constantes y acumulacion de checks sin branches visibles; no reemplaza una auditoria side-channel.
- Bajo feature `pkix`: `der`, `spki`, `pkcs8`, `x509-cert`, `const-oid`, `pem-rfc7468`. Justificados porque RFC 9881 es DER/ASN.1/PKIX y escribir DER a mano aumenta riesgo de interoperabilidad.
- Opcional dev: `hex-literal` para vectores cortos y snapshots.

Evitar por defecto:

- Crates "dilithium" o "mldsa" que oculten el algoritmo completo, salvo como oracle de comparacion en tests diferenciales. La POC debe poder medir sus propios pasos internos.
- ASN.1 construido con strings o concatenacion manual de bytes.

## Resultado estandar medible

La POC se considera alineada con el estandar cuando:

- Las constantes y tamanos coinciden con FIPS 204.
- KeyGen/Sign/Verify pasan KATs oficiales o vectores equivalentes generados desde semillas conocidas.
- Firmas validas verifican y mutaciones pequenas fallan.
- Decode rechaza longitudes y hints malformados.
- RFC 9881:
  - usa los tres OIDs correctos;
  - no codifica parametros en `AlgorithmIdentifier`;
  - usa public key cruda FIPS dentro de `subjectPublicKey` BIT STRING;
  - soporta private key seed/expanded/both;
  - rechaza seed+expanded inconsistente cuando se pide consistency check;
  - no acepta HashML-DSA para PKIX.
- Benchmarks reportan keygen/sign/verify por parametro y distribucion de repeticiones del loop de firma.

## Fuentes primarias

- FIPS 204, "Module-Lattice-Based Digital Signature Standard", NIST, publicado el 13 de agosto de 2024: <https://doi.org/10.6028/NIST.FIPS.204>
- RFC 9881, "Internet X.509 Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)", octubre de 2025: <https://datatracker.ietf.org/doc/rfc9881/>

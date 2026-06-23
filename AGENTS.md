# AGENTS.md

Este repo es una POC de ML-DSA en Rust. La referencia normativa para el algoritmo es FIPS 204; la referencia normativa para PKIX/X.509 es RFC 9881.

## Como leer las fuentes

- FIPS 204 local: `docs/NIST.FIPS.204.pdf`.
- Para buscar texto de FIPS:
  - `pdftotext docs/NIST.FIPS.204.pdf /tmp/fips204.txt`
  - `rg -n "ML-DSA-44|Algorithm 7|Table 1" /tmp/fips204.txt`
- RFC 9881 local: `docs/rfc9881.txt`.
- `docs/CRYSTALS_Dilithium_Clean.md` es contexto tecnico util, pero no reemplaza FIPS 204 ni RFC 9881.
- RFC 9882 esta en `docs/rfc9882.txt`, pero el alcance pedido es RFC 9881. Usarlo solo como referencia de CMS si una tarea lo pide.

Fuentes oficiales verificadas:

- FIPS 204: https://doi.org/10.6028/NIST.FIPS.204
- RFC 9881: https://datatracker.ietf.org/doc/rfc9881/

## Frontera normativa

- FIPS 204 define ML-DSA: KeyGen, Sign, Verify, parametros, codificacion cruda de claves/firmas, sampling, SHAKE, NTT, rejection loop.
- RFC 9881 define como usar ML-DSA en PKIX/X.509: OIDs, AlgorithmIdentifier, SubjectPublicKeyInfo, keyUsage y formatos ASN.1 de private key.
- ML-DSA deriva de CRYSTALS-Dilithium, pero ML-DSA y Dilithium historico no son compatibles byte a byte. No usar vectores Dilithium como prueba de conformidad ML-DSA salvo que esten explicitamente adaptados.
- Para PKIX, RFC 9881 especifica pure ML-DSA. HashML-DSA de FIPS 204 no debe usarse en certificados X.509 para CRL, OCSP, certificate issuance ni protocolos PKIX relacionados.

## Parametros FIPS 204

Constantes globales:

- `n = 256`
- `q = 8380417`
- `zeta = 1753`
- `d = 13`

Parameter sets:

| Set | Categoria | `(k,l)` | `eta` | `tau` | `lambda` | `gamma1` | `gamma2` | `beta` | `omega` | pk | sk expanded | sig |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-DSA-44 | 2 | `(4,4)` | 2 | 39 | 128 | `2^17` | `(q-1)/88` | 78 | 80 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 3 | `(6,5)` | 4 | 49 | 192 | `2^19` | `(q-1)/32` | 196 | 55 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 5 | `(8,7)` | 2 | 60 | 256 | `2^19` | `(q-1)/32` | 120 | 75 | 2592 | 4896 | 4627 |

FIPS tambien lista entropia del desafio y repeticiones esperadas:

- ML-DSA-44: challenge entropy 192, signing loop esperado 4.25.
- ML-DSA-65: challenge entropy 225, signing loop esperado 5.1.
- ML-DSA-87: challenge entropy 257, signing loop esperado 3.85.

## Flujo FIPS 204

KeyGen externo:

- Genera seed `xi` de 32 bytes.
- Llama a `ML-DSA.KeyGen_internal(xi)`.

KeyGen interno:

- `H(xi || k || l, 128)` produce `rho` de 32 bytes, `rho_prime` de 64 bytes y `K` de 32 bytes.
- `ExpandA(rho)` genera `A` en representacion NTT.
- `ExpandS(rho_prime)` genera `s1` y `s2` con coeficientes en `[-eta, eta]`.
- Calcula `t = A s1 + s2`.
- `Power2Round(t)` produce `t1` y `t0`.
- `pk = pkEncode(rho, t1)`.
- `tr = H(pk, 64)`.
- `sk = skEncode(rho, K, tr, s1, s2, t0)`.

Sign externo:

- Recibe `sk`, mensaje `M` y contexto `ctx`.
- Si `ctx.len() > 255`, falla.
- Variante hedged por defecto: genera `rnd` de 32 bytes.
- Variante deterministica solo para tests/KAT: `rnd = [0; 32]`.
- Forma `M' = 0x00 || len(ctx) || ctx || M` a nivel de bits/bytes segun FIPS.
- Llama a `ML-DSA.Sign_internal(sk, M', rnd)`.

Sign interno:

- Decodea `sk` en `rho, K, tr, s1, s2, t0`.
- `mu = H(tr || M', 64)`.
- `rho_second = H(K || rnd || mu, 64)`.
- Loop de rechazo:
  - `y = ExpandMask(rho_second, kappa)`.
  - `w = A y`.
  - `w1 = HighBits(w)`.
  - `c_tilde = H(mu || w1Encode(w1), lambda/4)`.
  - `c = SampleInBall(c_tilde)`.
  - `z = y + c s1`.
  - `r0 = LowBits(w - c s2)`.
  - Rechazar si `||z||inf >= gamma1 - beta` o `||r0||inf >= gamma2 - beta`.
  - Calcular `h = MakeHint(-c t0, w - c s2 + c t0)`.
  - Rechazar si `||c t0||inf >= gamma2` o si la cantidad de unos en `h` supera `omega`.
  - Incrementar `kappa` por `l`.
- Firma cruda: `sigEncode(c_tilde, z mod q, h)`.

Verify externo:

- Recibe `pk`, `M`, `sig`, `ctx`.
- Si `ctx.len() > 255`, falla.
- Forma el mismo `M'`.
- Llama a `ML-DSA.Verify_internal(pk, M', sig)`.

Verify interno:

- Rechazar si `pk` o `sig` tienen longitud distinta a la especificada para el parametro.
- Decodear `pk` en `rho, t1`.
- Decodear `sig` en `c_tilde, z, h`; si `h` esta mal codificado, devolver `false`.
- `A = ExpandA(rho)`.
- `tr = H(pk, 64)`.
- `mu = H(tr || M', 64)`.
- `c = SampleInBall(c_tilde)`.
- Reconstruir `w_approx = A z - c t1 * 2^d`.
- `w1_prime = UseHint(h, w_approx)`.
- Verificar rango de `z`, cantidad de hints y que `c_tilde == H(mu || w1Encode(w1_prime), lambda/4)`.

## Limites FIPS 204 para loops/XOF

Por defecto, no limitar loops ni bytes XOF. Si una implementacion decide limitar, no usar limites menores que:

| Algoritmo | Iteraciones minimas | Bytes XOF minimos |
| --- | ---: | ---: |
| `ML-DSA.Sign_internal` | 814 | N/A |
| `RejBoundedPoly` | 481 | 481 |
| `RejNTTPoly` | 298 | 894 |
| `SampleInBall` | 121 | 221 |

Si se alcanza un limite, destruir intermedios y devolver siempre el mismo error/valor para ese caso.

## RFC 9881 / PKIX

OIDs NIST registrados:

- `id-ml-dsa-44 = 2.16.840.1.101.3.4.3.17`
- `id-ml-dsa-65 = 2.16.840.1.101.3.4.3.18`
- `id-ml-dsa-87 = 2.16.840.1.101.3.4.3.19`

Reglas obligatorias:

- `AlgorithmIdentifier.parameters` debe estar ausente. No codificar `NULL`.
- En certificados y CRLs, `signatureAlgorithm` usa uno de los OIDs anteriores y sin parametros.
- `signatureValue` contiene la firma ML-DSA correspondiente sobre el DER de `TBSCertificate` o `TBSCertList`.
- El contexto `ctx` de FIPS para firmas PKIX queda en su default: string vacio.
- `SubjectPublicKeyInfo.subjectPublicKey` contiene la public key cruda FIPS en BIT STRING.
- Cuando la public key aparece fuera de SPKI en un entorno ASN.1, puede codificarse como OCTET STRING de tamano:
  - 1312 para ML-DSA-44.
  - 1952 para ML-DSA-65.
  - 2592 para ML-DSA-87.

KeyUsage:

- Si `keyUsage` esta presente con una public key ML-DSA, debe incluir al menos uno de:
  - `digitalSignature`
  - `nonRepudiation`
  - `keyCertSign`
  - `cRLSign`
- No debe incluir:
  - `keyEncipherment`
  - `dataEncipherment`
  - `keyAgreement`
  - `encipherOnly`
  - `decipherOnly`

Private key RFC 9881:

- FIPS reconoce seed de 32 bytes y expanded private key.
- RFC 9881 recomienda seed-only por eficiencia.
- En `OneAsymmetricKey.privateKey`, el contenido es un DER CHOICE:
  - `seed [0] OCTET STRING (SIZE 32)`, tag raw `0x80`, total 34 bytes con tag y length.
  - `expandedKey OCTET STRING`, tag `0x04`, tamanos 2560/4032/4896.
  - `both SEQUENCE`, tag `0x30`, con seed y expandedKey.
- Al parsear, decidir por tag ASN.1, no por heuristica de longitud.
- Si se recibe `both`, deberia ejecutarse consistency check: regenerar expanded key desde seed con `ML-DSA.KeyGen_internal(seed)` y comparar byte a byte. Si no coincide y se hizo el check, rechazar como malformed.
- Si se descarto el seed y solo queda expandedKey, no se puede reconstruir el seed.

## Benchmarks y experimentos

Benchmarks minimos:

- `keygen`, `sign`, `verify` por ML-DSA-44/65/87.
- NTT/inverse NTT.
- `ExpandA`, `ExpandS`, `ExpandMask`, `SampleInBall`.
- Encode/decode de pk/sk/sig.
- PKIX DER encode/decode bajo feature `pkix`.

Metricas de parametros:

- Tamanos de pk/sk/sig.
- Repeticiones del loop de firma.
- Distribucion de `||z||inf`, `||r0||inf`, `||c t0||inf`.
- Cantidad de hints.
- Porcentaje de rechazos por condicion.
- Latencia y throughput de keygen/sign/verify.

Los experimentos con parametros alterados deben vivir bajo `experimental-params` y no deben exponer APIs conformes. Una firma generada con parametros alterados no es ML-DSA FIPS ni RFC 9881 aunque use nombres parecidos.

## Dependencias sugeridas

- `sha3` para SHAKE128/SHAKE256.
- `rand_core`; `rand_chacha` solo dev/test para reproducibilidad.
- `criterion` solo dev para benchmarks.
- `zeroize` para secretos.
- `subtle` para comparaciones/checks constantes donde aplique.
- Bajo feature `pkix`: `der`, `spki`, `pkcs8`, `x509-cert`, `const-oid`, `pem-rfc7468`.

No usar un crate ML-DSA completo como implementacion principal. Puede usarse solo como oracle de tests diferenciales, si se documenta.

## Reglas de implementacion

- Preferir Rust seguro; evitar `unsafe`.
- Separar API segura de API de test:
  - segura: randomness generado dentro del modulo criptografico;
  - test/KAT: seeds y `rnd` inyectables;
  - experimental: parametros alterados.
- No aceptar longitudes flexibles para pk/sig en verify.
- No usar string concatenation manual para DER.
- No filtrar intermedios de intentos rechazados.
- Documentar cualquier branch o acceso a memoria dependiente de secreto.
- El objetivo de la POC es medicion y conformidad, no certificacion FIPS.

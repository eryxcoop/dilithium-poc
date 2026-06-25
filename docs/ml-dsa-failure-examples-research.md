# ML-DSA failure examples: research notes for educational challenges

Este documento es una base para construir ejercicios educativos al estilo
Cryptopals/CryptoHack, pero centrados en errores de implementacion de ML-DSA.
La idea no es modificar el `src/` conforme a FIPS 204, sino crear ejemplos
aislados que muestren que cambios aparentemente chicos pueden convertir una
firma valida, interoperable o "casi correcta" en recuperacion de clave,
forja universal, DoS o perdida de conformidad.

## Fuentes usadas

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204). Fuente normativa para ML-DSA.
- [CRYSTALS-Dilithium specification v3.1](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf). Fuente tecnica para el diseno, pruebas de seguridad y racional de parametros.
- [IETF CFRG draft: Security Considerations for ML-DSA](https://www.ietf.org/archive/id/draft-connolly-cfrg-ml-dsa-security-considerations-02.html). Resume riesgos de signing, fault resistance y despliegue.
- [Correction Fault Attacks on Randomized CRYSTALS-Dilithium](https://oa.tib.eu/renate/bitstreams/416ce17e-4a1d-46ce-b881-7e761310045f/download). Muestra ataques de recuperacion de clave contra signing randomized/hedged bajo faults.
- [A Single-Trace Fault Injection Attack on Hedged ML-DSA](https://www.diva-portal.org/smash/get/diva2%3A1890088/FULLTEXT02.pdf). Discute nonce reuse inducido por faults y ataques a hedged ML-DSA.
- [NCC Group: Lattice Signatures, Fiat-Shamir with Aborts](https://www.nccgroup.com/research/building-intuition-for-lattice-based-signatures-part-2-fiat-shamir-with-aborts/). Buena referencia pedagogica para explicar por que rejection sampling importa.
- [Daniel J. Bernstein, Exploiting ML-DSA bugs](https://cr.yp.to/papers/mldsa-20260601.pdf) y un [resumen tecnico externo](https://postquantum.com/security-pqc/bernstein-exploiting-mldsa-bugs/). Usar con cuidado: es material reciente y con tesis fuerte, pero muy util para diseñar demos de bugs que pasan tests funcionales.
- Referencias locales del repo: `docs/NIST.FIPS.204.pdf`, `docs/CRYSTALS_Dilithium_Clean.md`, `docs/rfc9881.txt`.

## Notación usada

El documento usa simbolos Unicode para mantener la lectura cerca de FIPS 204 y
de las rustdocs del repo: `ρ` para la seed publica de `ExpandA`, `ρ′` para la
seed secreta de `ExpandS`, `ρ″` para `H(K || rnd || μ, 64)`, `μ` para el
representante del mensaje, `c̃` para el challenge hash, `Â` para `A_hat`, `∞`
para la norma infinito, y `η`, `τ`, `λ`, `γ₁`, `γ₂`, `β`, `ω` para las letras
griegas. Los nombres ASCII se conservan solo cuando son nombres de archivo,
identificadores de codigo o IDs de challenges.

## Lectura rápida

Los errores mas fuertes para convertir en challenges son los que permiten
recuperacion de clave o forja universal con pocas firmas. La familia mas clara
es la reutilizacion de `y`, el "nonce" interno de Dilithium/ML-DSA: si dos
firmas usan el mismo `y` con desafios distintos, entonces `z - z' = (c - c')s1`
y el atacante obtiene ecuaciones directas sobre el secreto. FIPS 204 advierte
que `y` no debe reutilizarse ni ser adivinable; los trabajos de fault attacks
explican como faults pueden inducir escenarios de reuse o revelar valores
lineales relacionados con `s1`.

El segundo grupo fuerte son bugs de distribucion que aun producen firmas
validas para verificadores correctos. El ejemplo moderno es la clase "AABBCC":
si el sampler o unpacker de `y` repite patrones de coeficientes, las firmas
pueden seguir verificando, pero la estructura publica de muchas firmas permite
resolver sistemas lineales y recuperar una clave equivalente. Este tipo de bug
es pedagogicamente potente porque enseña que los KATs y los tests de
interoperabilidad no bastan si el bug afecta tambien al generador de vectores
o si las firmas siguen estando dentro del lenguaje aceptado por el verificador.

El tercer grupo son omisiones del verifier. Si no se valida estrictamente
`z`, `h`, `c̃`, longitudes y codificaciones, el adversario puede sacar el
esquema de la reduccion de seguridad: ya no esta produciendo un vector corto
que corresponde al problema MSIS/SelfTargetMSIS analizado, sino un objeto fuera
del dominio. Algunas omisiones dan "solo" maleabilidad o aceptacion de basura;
otras, combinadas con parametros de juguete, permiten construir forjas con
busqueda exhaustiva.

## Modelo para los challenges

Para mantener seguro el `src/` principal, cada challenge deberia vivir fuera
del modulo conforme, por ejemplo bajo una futura carpeta `challenges/` o
`examples/failures/`. Cada ejercicio deberia tener tres piezas:

1. Un modulo vulnerable autocontenido que reutiliza partes sanas del crate pero
   cambia una sola cosa: sampler, parametro, check o encoding.
2. Un test/runner que demuestra el fallo con parametros reducidos o con
   ML-DSA-44 cuando el ataque es practico.
3. Un README corto con "objetivo", "pista matematica", "exploit esperado" y
   "por que FIPS lo evita".

No todos los fallos de abajo son ataques conocidos contra los parametros FIPS
reales. Algunos son ejercicios de juguete para hacer visible el rol de un
parametro. En cada entrada marco el impacto mas fuerte razonable y el tipo de
demo recomendado.

## Ranking de problemas para clase

1. Reutilizar `y` / `ρ″,κ`: recuperacion de `s1` y forja universal. Dos firmas
   bastan en el caso limpio; es el paralelo ML-DSA del nonce reuse clasico.
2. Sampler de `y` con patron AABBCC/A0B0: recuperacion de clave equivalente.
   Puede producir firmas validas que pasan tests funcionales.
3. Omitir el chequeo de `c̃ == H(μ || w1′)`: forja trivial. El verifier deja de
   estar ligado al mensaje y al compromiso.
4. Omitir `||z||∞ < γ₁ - β`: forjas fuera de la reduccion y busqueda mas facil
   en toy params. Enseña por que la "cortedad" no es decorativa.
5. Omitir validacion de hints / `ω`: maleabilidad o forjas asistidas por hints.
   Muestra que los hints son datos adversarios, no metadata inocente.
6. Usar `λ`, `τ`, `k,l,n` demasiado chicos: busqueda exhaustiva o algebra
   lineal. Ideal para versiones mini que se rompen en segundos.

## Problemas por parametro

### `n`: grado del anillo

`n = 256` fija que se trabaja en `R_q = ℤ_q[X]/(X²⁵⁶ + 1)` y multiplica las
dimensiones efectivas de MLWE/MSIS. Si un ejemplo reduce `n` a 16 o 32 para
"hacerlo mas rapido", el problema de reticulas deja de tener el tamaño
analizado y muchas ecuaciones pasan a poder resolverse por algebra lineal o
busqueda directa. El challenge recomendado es una version toy con `n = 16`,
misma estructura de firma y secretos pequeños: recolectar firmas y recuperar
`s1` resolviendo el sistema inducido por `z = y + c s1`. Impacto: recuperacion
de clave en parametros reducidos; no representa un ataque contra FIPS, pero
enseña que `n` no es solo una constante de performance.

### `q`: modulo primo

`q = 8380417 = 2²³ - 2¹³ + 1` es primo y compatible con una NTT eficiente.
Cambiarlo por un modulo chico, compuesto o no compatible rompe simultaneamente
la aritmetica, la distribucion de `RejNTTPoly`, la reduccion a MLWE/MSIS y la
semantica de `HighBits/LowBits`. El problema fuerte en una demo es elegir un
`q` chico para que las operaciones de ring queden en un espacio enumerable:
el atacante puede reconstruir secretos por busqueda o encontrar colisiones de
compromiso con probabilidad visible. Impacto: recuperacion o forja en esquema
toy; en una implementacion real, normalmente seria fallo de interoperabilidad,
pero si signer y verifier comparten el `q` equivocado estan usando otro esquema.

### `ζ`: raiz para NTT

`ζ = 1753` es parte de la representacion NTT concreta. Si se usa una raiz
que no tiene el orden esperado, la transformada deja de ser una representacion
fiel de la multiplicacion en `R_q`. El bug mas didactico es usar una `ζ`
degenerada que haga que varias entradas distintas tengan la misma imagen NTT:
las multiplicaciones `Â y` y `Â s1` pierden rango, y aparecen colisiones o
ecuaciones mas faciles. Impacto: normalmente fallo de correctitud; en un
challenge controlado, rank loss que facilita recuperar secretos o producir
firmas que verifican bajo el verifier igualmente roto.

### `d`: bits bajos descartados de `t`

`d = 13` controla `Power2Round(t) = (t1,t0)`: el public key publica `t1` y el
secret key conserva `t0`. Si `d` sube, el public key se comprime mas, pero
`t0` crece y el termino `c t0` que el signer debe controlar se vuelve mas
peligroso; la especificacion Dilithium liga esto directamente a las cotas SIS
de la prueba. El challenge recomendado es un signer/verifier experimental con
`d` demasiado grande y sin el rechazo `||c t0||∞ < γ₂`: el verifier
acepta aproximaciones demasiado gruesas, y el atacante aprende que comprimir
mas la clave publica exige pagar con checks mas estrictos. Impacto: forjas o
aceptacion de firmas no conformes en parametros reducidos.

### `k`: filas de `A` y dimension de `s2,t`

`k` fija cuantas ecuaciones publicas hay en `t = A s1 + s2` y cuantas
coordenadas se verifican en `w1`. Bajar `k` reduce la dimension del problema
MLWE y tambien reduce el numero de restricciones que un forgery debe satisfacer.
Un challenge bueno es `k = 1` con `l` chico: el atacante ve una sola fila de
ecuaciones por coeficiente y puede buscar secretos cortos o construir colisiones
de `HighBits(Az - c t1 2ᵈ)` mucho mas facilmente. Impacto: recuperacion o
forja en parametros toy; en FIPS, `k` es parte central del nivel de seguridad.

### `l`: columnas de `A` y dimension de `s1,y,z`

`l` determina cuantos polinomios tiene `s1` y cuantos componentes tiene el
masking vector `y`. Si `l` se reduce, el secreto tiene menos dimension; si se
incrementa sin recalibrar `γ₁`, `β` y tamaños, crece la probabilidad de
rechazo y cambia la cota MSIS. El challenge recomendado es usar `l = 1` para
mostrar que nonce reuse se vuelve casi una ecuacion univariante: dos firmas con
el mismo `y` dan `(z-z') = (c-c')s1`, y la division/inversion en el ring toy
recupera `s1`. Impacto: recuperacion de clave muy visual.

### `η`: cota de `s1,s2`

`η` define la distribucion secreta: `s1,s2` tienen coeficientes en
`[-η, η]`. Si `η` es demasiado bajo, el secreto pierde entropia y se
vuelve mas facil de enumerar; si el sampler no boundea correctamente `η`, la
clave puede salirse de la distribucion que sostiene MLWE y de la cota
`β = τ · η`. Un challenge potente es `η = 0` o `η = 1`: con pocas
firmas y la ecuacion publica `t = A s1 + s2`, el alumno puede hacer busqueda
por coeficiente o por polinomio en un parametro mini. Impacto: recuperacion de
clave en toy params; en parametros reales, cambiar `η` sin reanalizar rompe
la hipotesis de distribucion y los margenes de rechazo.

### `τ`: peso del challenge `c`

`τ` fija cuantos coeficientes no nulos tiene el challenge. Si `τ` baja,
la entropia de `c` cae y `c s1`, `c s2`, `c t0` involucran menos secreto; en
el extremo `τ = 0`, `c` es siempre cero. Ese extremo da un challenge hermoso:
el atacante elige un `z` corto, calcula `w1′ = HighBits(Az)`, computa
`c̃ = H(μ || w1′)`, y como `SampleInBall(c̃)` siempre devuelve el
polinomio cero, obtiene una firma valida sin conocer la clave. Impacto: forja
universal en el esquema modificado. Es la demostracion mas clara de que el
challenge no puede tener poca entropia aunque todo lo demas "compile".

### `λ`: seguridad del hash de compromiso

`λ` determina la longitud de `c̃` (`λ / 4` bytes en FIPS 204).
Si se trunca demasiado, el atacante puede buscar colisiones o preimagenes del
hash `H(μ || w1)` con trabajo pequeno. Un challenge concreto es fijar
`λ = 16` o `24`, mantener un verifier correcto salvo por esa truncacion,
y pedir encontrar dos mensajes o dos `w1` que produzcan el mismo `c̃`.
Impacto: forja o reutilizacion de challenge por busqueda exhaustiva en minutos
o segundos, segun el toy target. En FIPS, `λ` tambien separa los niveles
de seguridad 2, 3 y 5.

### `γ₁`: rango del masking vector `y`

`γ₁` define el rango de `y` y el bound de `z`. Si `γ₁` es demasiado
chico, `z = y + c s1` deja de ocultar bien a `c s1`: los rechazos y las
posiciones cercanas al borde empiezan a depender del secreto. Si `γ₁` es
demasiado grande, las firmas crecen y la cota SIS del forgery se relaja. El
challenge recomendado es un signer con `γ₁` pequeño que no rechaza
correctamente bordes: con muchas firmas, los alumnos estiman sesgos en los
coeficientes de `z` condicionados por `c` y recuperan signos o valores de
`s1`. Impacto: leakage estadistico de clave; mas pedagogico que inmediato.

### `γ₂`: escala de `HighBits/LowBits` y hints

`γ₂` fija la escala `α = 2γ₂` para descomponer `w` en parte alta
y baja. Si `γ₂` es demasiado grande, hay menos valores posibles de `w1` y
el compromiso pierde granularidad; si es demasiado chico, los carries se
vuelven frecuentes y los hints dominan la firma. Un challenge didactico es
usar un `γ₂` enorme para que `w1` tenga muy pocos valores y luego buscar
forjas por colision de `H(μ || w1′)` en parametros reducidos. Otro challenge
es usar `γ₂` chico y omitir el chequeo de hints, mostrando que el atacante
puede "arreglar" demasiados bits altos. Impacto: forja en toy params o DoS por
rechazo excesivo.

### `β`: margen `τ · η`

`β` es el margen que cubre el peor caso de `c s1` y `c s2`. Los checks
`||z||∞ < γ₁ - β` y `||r0||∞ < γ₂ - β` existen para que la
salida aceptada no revele cuanto se acerco `y` al borde despues de sumar el
secreto. Si `β` se calcula demasiado bajo o se ignora, el signer acepta
firmas que deberian abortar; esas firmas tienen una distribucion dependiente de
`s1,s2`. El challenge recomendado es reducir artificialmente `β` y recolectar
muchas firmas para hacer un ataque de sesgo de borde sobre un coeficiente.
Impacto: leakage estadistico; con parametros muy chicos puede escalar a
recuperacion de clave.

### `ω`: maximo peso del hint `h`

`ω` limita cuantos coeficientes pueden necesitar correccion por hints. Si
el verifier no controla `ω`, el atacante puede entregar hints densos que
le dan demasiada libertad para reconstruir `w1′`; si el decoder tampoco rechaza
codificaciones malformadas, aparecen maleabilidad y dobles representaciones.
Un challenge muy concreto es "verifier sin `ω`": construir una firma donde
`h` corrige muchas posiciones para hacer coincidir el hash, y luego mostrar que
el verifier FIPS la rechaza. Impacto: forja asistida por hints en toy params o
perdida de strong unforgeability; FIPS 204 precisamente insiste en decodificar
estrictamente `h`.

### Tamanos `pk`, `sk`, `sig`

Los tamaños no son parametros algebraicos, pero si el verifier acepta longitudes
flexibles o trailing bytes, el formato deja de ser canonico. El problema fuerte
no suele ser recuperacion de clave sino malleability, confusiones entre capas y
diferencias de comportamiento entre implementaciones. El challenge recomendado
es un parser permisivo que acepta una firma valida con basura al final o un
`pk` con longitud incorrecta; luego se compara contra el verifier estricto.
Impacto: bypass de validaciones de protocolo o test de interoperabilidad falso.

### `ρ`: seed publica de `ExpandA`

`ρ` no es secreto, pero define la matriz publica `Â = ExpandA(ρ)`. Si un bug ignora indices
de fila/columna o reutiliza la misma semilla para varias entradas, `Â` puede
perder rango o adquirir estructura repetida. Este es pariente conceptual de los
bugs AABBCC: la aritmetica puede seguir produciendo firmas que verifican, pero
el sistema publico tiene simetrias explotables. El challenge recomendado es
`ExpandA` que usa solo `ρ || row` o solo `ρ || col`, creando columnas
repetidas; los alumnos deben detectar la repeticion y recuperar una clave
equivalente o forjar en parametros mini. Impacto: recuperacion/forja por rank
loss.

### `ρ′`: seed secreta de `ExpandS`

`ρ′` expande `s1,s2`. Si se reutiliza entre claves o se deriva sin
incluir correctamente `k,l`, dos keypairs pueden compartir secretos o tener
secretos correlacionados. Un challenge posible es generar dos claves con el
mismo `ρ′` y distinto `ρ`: el atacante compara `t = A s1 + s2` bajo
matrices conocidas y explota que `s1,s2` son los mismos o estan correlacionados.
Impacto: recuperacion multi-key en parametros reducidos; en FIPS, la expansion
desde `xi || k || l` evita colisiones entre parameter sets.

### `K` y `rnd`: seed de masking en signing

`K` y `rnd` alimentan `ρ″ = H(K || rnd || μ, 64)`. Si `rnd` se fija,
se trunca o se reutiliza de forma que `ρ″` se repita para dos mensajes,
se repite `y` y aparece recuperacion de `s1`. FIPS permite modo deterministico
para KATs, pero las consideraciones de seguridad recomiendan hedged signing en
plataformas con faults/side channels. El challenge principal debe ser "nonce
reuse": forzar mismo `ρ″,κ`, generar dos firmas con desafios
distintos y recuperar `s1` o una clave equivalente. Impacto: catastrofico,
recuperacion de clave y forja universal.

## Problemas por chequeo del verifier

### No comparar `c̃`

Si el verifier no comprueba que `c̃ == H(μ || w1Encode(w1′))`, se elimina
el Fiat-Shamir transform: el adversario puede elegir un challenge y una respuesta
sin que esten atados al mensaje ni al compromiso. El challenge mas simple es
quitar esa comparacion y mostrar que una firma aleatoria estructuralmente valida
puede pasar. Impacto: forja trivial.

### No verificar `||z||∞ < γ₁ - β`

La cota sobre `z` es lo que convierte una aceptacion en una solucion corta del
problema MSIS analizado. Sin esa cota, el atacante puede usar respuestas grandes
para satisfacer ecuaciones que no deberian contar como forgeries criptograficas.
El challenge recomendado es un verifier sin bound de `z` y parametros mini:
buscar `z` grande hasta que el hash coincida, o construir `z` por algebra lineal.
Impacto: forja fuera de dominio.

### No validar `h` y `ω`

Los hints son entrada adversaria. Si se aceptan hints malformados, posiciones
duplicadas, pesos mayores que `ω` o codificaciones no canonicas, el verifier
puede reconstruir un `w1′` que ningun signer FIPS habria emitido. El challenge
debe comparar dos firmas distintas para el mismo mensaje que solo difieren en
representacion de hints: una implementacion permisiva acepta ambas; la estricta
rechaza la malformada. Impacto: maleabilidad y perdida de strong unforgeability,
con potencial de forja en parametros reducidos.

### No verificar longitudes exactas

FIPS fija tamaños exactos para public keys y signatures. Si el verifier permite
longitudes flexibles, se abren bugs de parsing diferencial: una capa superior
puede hashear una secuencia de bytes y otra verificar otra, o dos firmas
distintas pueden representar el mismo objeto interno. El challenge recomendado
es trailing-byte malleability: construir `sig || basura` que verifica en el
parser permisivo pero no en el estricto. Impacto: confusion de protocolo.

### No bindear contexto `ctx`

El formato externo firma `M' = 0x00 || len(ctx) || ctx || M`. Si se omite `ctx`
o su longitud, una firma valida en un protocolo puede replayearse en otro. El
challenge recomendado es dos dominios, por ejemplo `"login"` y `"firmware"`,
donde el verifier vulnerable ignora `ctx` y acepta la misma firma. Impacto:
cross-protocol replay, no recuperacion de clave.

## Plan sugerido de implementacion de challenges

1. `nonce_reuse`: forzar el mismo `y` para dos mensajes y recuperar `s1`.
2. `tau_zero_forgery`: parameter set toy con `τ = 0` y forja universal.
3. `lambda_too_short`: truncar `c̃` y buscar colision de challenge.
4. `eta_too_small`: `η = 0/1` y recuperacion por busqueda.
5. `verifier_no_ctilde`: quitar el hash check y demostrar forja trivial.
6. `verifier_no_z_bound`: aceptar `z` grande y construir forja en toy params.
7. `verifier_no_omega`: hints densos/malformados aceptados por no controlar `ω`.
8. `expand_a_repeated_columns`: bug de indices en `ρ || row/col`.
9. `gamma1_edge_leak`: margen chico en `γ₁` y ataque estadistico por bordes.
10. `trailing_bytes`: parser permisivo contra parser estricto.

Para cada challenge, conviene declarar explicitamente si usa parametros FIPS
reales o parametros toy. Los challenges de recuperacion catastrofica por nonce
reuse y patrones de `y` pueden ser realistas; los de `n,q,k,l,λ,τ`
deberian ser toy para que la explotacion sea rapida y segura en clase.

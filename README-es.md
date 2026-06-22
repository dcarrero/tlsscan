# tlsscan

> English: [README.md](README.md) · Español: [README-es.md](README-es.md)

Un escáner de configuración TLS escrito en Go, **sin dependencias externas**. Usa
**únicamente la biblioteca estándar de Go** (`crypto/tls`, `crypto/x509`, `net`,
`encoding/json`), implementa la **SSL Labs Server Rating Guide** (una especificación
pública) y **no contiene código GPL** — es una reimplementación limpia bajo licencia MIT
de la *spec*, no del código de testssl.sh ni de nadie.

- **Module path:** `github.com/dcarrero/tlsscan`
- **Licencia:** MIT (ver [LICENSE](LICENSE))
- **Go:** 1.22+

Nace como motor TLS de [HeaderForge](https://headerforge.io) pero se sostiene por sí
mismo: una alternativa con licencia permisiva a testssl.sh (que es GPLv2), pensada para
integrarse en productos comerciales sin fricción de licencia.

## Por qué existe

- **Licencia limpia.** testssl.sh es excelente pero GPLv2; envolverlo en un SaaS
  comercial es legalmente turbio. tlsscan es MIT: úsalo en lo que quieras.
- **Cero dependencias.** Solo la biblioteca estándar de Go. No reimplementa
  criptografía: hace handshakes reales y observa qué acepta el servidor.
- **Tres caras, un motor.** Librería, CLI y servicio HTTP comparten el mismo paquete
  `pkg/tlsscan`.

## Las tres formas de uso

### 1. Como librería

```go
import "github.com/dcarrero/tlsscan/pkg/tlsscan"

res, err := tlsscan.Scan(ctx, tlsscan.Options{
    Host:       "example.com",
    Port:       443,                 // por defecto 443
    Timeout:    15 * time.Second,    // por defecto 15s
    CheckVulns: true,                // ejecuta los probes activos de vulns (más lento)
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(res.Grade)          // ej. "A+"
fmt.Println(res.Rating.Numeric) // 0-100
```

`Scan` devuelve un `*Result` cuyos nombres de campo JSON son un contrato estable
(consumido por el gateway de HeaderForge). Ver `pkg/tlsscan/types.go` para el struct
completo.

### 2. Como CLI (`cmd/tlsscan`)

```bash
go run ./cmd/tlsscan example.com
go run ./cmd/tlsscan -json -vulns badssl.com
```

Flags:

| Flag | Tipo | Por defecto | Significado |
|------|------|-------------|-------------|
| `-port` | int | `443` | Puerto destino. |
| `-timeout` | duration | `15s` | Timeout por operación (duración Go, ej. `12s`, `1m`). |
| `-vulns` | bool | `false` | Ejecuta los probes de vulnerabilidades (más lento). |
| `-json` | bool | `false` | Imprime el `Result` en JSON en vez de texto legible. |

El host es el único argumento posicional: `tlsscan [flags] <host>`.

### 3. Como servicio HTTP (`cmd/headerforge-tls`)

```bash
go run ./cmd/headerforge-tls
# Escucha en 127.0.0.1:8081 por defecto. Sobrescribe con TLS_SCAN_LISTEN.
TLS_SCAN_LISTEN=10.0.0.5:8081 go run ./cmd/headerforge-tls
```

Endpoints:

- `GET /healthz` → `200 ok`
- `POST /v1/scan` con un body JSON:

  ```json
  {
    "host": "example.com",
    "port": 443,
    "timeout_ms": 15000,
    "check_vulns": true
  }
  ```

  Devuelve el `Result` en JSON si tiene éxito, o `422` con `{"error": "..."}` si el scan
  no pudo ejecutarse (por ejemplo, si el guard anti-SSRF rechazó el objetivo).

El servicio escucha en una dirección privada/loopback por defecto y está pensado para
alcanzarse por red privada o tras un reverse proxy interno.

## Compilar

```bash
# Binario del servicio
go build -o bin/headerforge-tls ./cmd/headerforge-tls

# Binario de la CLI
go build -o bin/tlsscan ./cmd/tlsscan

# Binario estático para cualquier Linux (RunCloud, Stackscale): copiar y ejecutar, sin Go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" \
  -o bin/headerforge-tls ./cmd/headerforge-tls
```

## Qué detecta

### Protocolos

Cada versión de protocolo se prueba con un **handshake independiente** y la versión
negociada se verifica contra `ConnectionState` (defensa en profundidad):

- **TLS 1.0, 1.1, 1.2, 1.3** — vía `crypto/tls` de Go, un handshake fijado por versión.
- **SSLv3** — Go no lo negocia, así que tlsscan envía un **ClientHello SSLv3 construido a
  mano** a nivel de record e inspecciona la respuesta (alimenta POODLE). No implementa
  criptografía; solo decide si el servidor está dispuesto a hablar SSLv3.
- **SSLv2** — detectado con un **CLIENT-HELLO SSLv2** real (el framing legacy de cabecera
  de 2 bytes) buscando un SERVER-HELLO SSLv2; alimenta DROWN. No implementa criptografía.
- **ALPN / HTTP2** — detectados a partir del protocolo negociado durante la obtención del
  certificado.

### Certificado

El certificado leaf (y la cadena presentada) se analiza para:

- **Validez por fechas** (`not_before` / `not_after`) y días hasta la expiración.
- **Coincidencia de hostname** contra el host objetivo.
- Detección de **self-signed**.
- **`chain_complete`** — el leaf se verifica hasta una **raíz de confianza del sistema**
  usando solo los intermedios que presentó el servidor. El hostname no se comprueba en
  este paso a propósito (se reporta por separado), de modo que un certificado bien formado
  pero de host equivocado cuenta igualmente como cadena completa. Intermedios ausentes o
  una raíz desconocida/autofirmada dan `false`.
- **Tipo y bits de clave** (RSA / ECDSA).
- **Algoritmo de firma**, con **distrust de SHA-1** (una firma SHA-1 marca el certificado
  como distrustado).

### Ciphers

Para cada suite catalogada se intenta un handshake TLS 1.2 ofreciendo solo esa suite.
Las suites aceptadas se clasifican en **strong / weak / insecure**, y el **forward
secrecy** se infiere del intercambio de claves ECDHE/DHE.

### Vulnerabilidades (`CheckVulns: true`)

Todos los probes activos operan únicamente a nivel de **record / handshake**: emiten un
ClientHello (o CLIENT-HELLO SSLv2) construido a mano e interpretan solo los primeros
bytes de la respuesta. No implementan criptografía y nunca completan el handshake. Todos
fallan seguro: ante timeout, RST, alerta o respuesta ambigua devuelven el resultado no
vulnerable, nunca un falso positivo.

**Probes activos:**

- **Heartbleed (CVE-2014-0160)** — envía una petición Heartbeat malformada que declara
  16384 bytes de payload pero envía uno, y detecta una respuesta sobredimensionada (fuga
  de memoria). Los bytes filtrados nunca se inspeccionan ni almacenan.
- **SSLv2 / DROWN (CVE-2016-0800)** — envía un CLIENT-HELLO SSLv2 real (cabecera de
  record de 2 bytes, tipo de mensaje 0x01, versión 0x0002, cipher-specs de 3 bytes) y
  busca un SERVER-HELLO SSLv2 (tipo 0x04). DROWN se deriva del soporte de SSLv2.
- **FREAK (CVE-2015-0204)** — ofrece SOLO cipher suites RSA_EXPORT en un ClientHello
  TLS 1.0; un ServerHello en respuesta significa que el servidor aceptó una suite export.
- **Logjam (CVE-2015-4000)** — ofrece SOLO cipher suites DHE_EXPORT; un ServerHello en
  respuesta significa vulnerable.
- **TLS_FALLBACK_SCSV (RFC 7507)** — envía un ClientHello fijado una versión por debajo
  del máximo del servidor, incluyendo el marcador FALLBACK_SCSV (0x5600). Una alerta
  fatal `inappropriate_fallback` significa que la protección de downgrade está presente
  (`tls_fallback_scsv_missing: false`); un handshake completado en la versión inferior
  significa que falta (`true`). Solo se intenta si el servidor soporta más de una versión.
- **Renegociación insegura (RFC 5746)** — envía un ClientHello TLS 1.2 anunciando una
  extensión `renegotiation_info` vacía; un ServerHello que NO devuelve `renegotiation_info`
  (0xff01) carece de soporte de renegociación segura.

**Inferidas de los resultados de protocolo / cipher:**

- **POODLE** — inferido de que SSLv3 esté habilitado (probe SSLv3 real).
- **BEAST** — inferido de TLS 1.0 negociado junto con una cipher suite CBC.
- **SWEET32** — inferido de que se acepte un cifrado de bloque de 64 bits (3DES).

## Rating

La nota sigue la SSL Labs Server Rating Guide. La puntuación numérica es una combinación
ponderada de tres componentes:

| Componente | Peso |
|------------|------|
| Soporte de protocolos | 30% |
| Intercambio de claves (key exchange) | 30% |
| Fuerza de cifrado (cipher) | 40% |

`numeric = (protocol*30 + keyExchange*30 + cipher*40) / 100`, luego mapeado a una nota en
letra y ajustado por **grade caps**:

| Condición | Cap |
|-----------|-----|
| Problema de confianza del certificado (inválido / self-signed / distrustado / hostname no coincide) | **T** |
| Vulnerabilidad crítica (Heartbleed, DROWN, insecure renegotiation) | **F** |
| SSLv2 habilitado | **F** |
| SSLv3 habilitado | **C** |
| Cifrados export (FREAK / Logjam) | **C** |
| Sin forward secrecy | **B** |
| Cualquier cipher insecure | **C** |

Una configuración limpia con TLS 1.3, sin ciphers weak/insecure y >30 días hasta la
expiración obtiene **A+**.

Todo resultado incluye la **versión del ruleset** para que los scans sean reproducibles.
La constante actual es:

```
RulesetVersion = "ssllabs-rating-2009r"
```

## Testing

```bash
# Solo tests unitarios (sin red)
go test ./... -short

# Suite de red badssl — requiere salida a internet. Valida el grading contra
# subdominios de badssl.com con configuraciones TLS deliberadamente malas.
go test ./... -run BadSSL
```

## Limitaciones conocidas

tlsscan es honesto sobre qué está implementado y qué no. Lo siguiente está presente en el
esquema del `Result` (para que el contrato JSON sea estable) pero está **diferido** y
**siempre devuelve `false`** a día de hoy:

- **ROBOT**
- **GoldenDoodle**
- **ZombiePoodle**
- **SleepingPoodle**
- **CVE-2019-1559** (oráculo de padding de longitud cero)

Todos son oráculos de padding / estilo Bleichenbacher. Detectarlos de forma fiable exige
un **análisis diferencial de tiempos/respuestas** sobre muchos records construidos, lo que
conlleva un alto riesgo de falsos positivos contra balanceadores, WAFs y stacks TLS
tolerantes. En lugar de emitir hallazgos poco fiables, se dejan deliberadamente sin
implementar hasta poder probarlos sin falsos positivos.

Todo lo demás listado en *Vulnerabilidades* arriba — Heartbleed, SSLv2/DROWN, FREAK,
Logjam, TLS_FALLBACK_SCSV y renegociación insegura — es ya un probe activo real.

## Nota de seguridad / SSRF

Un escáner público nunca debe convertirse en una herramienta para alcanzar
infraestructura interna. tlsscan incluye un **guard de objetivos** que rechaza destinos
obviamente internos como defensa en profundidad: `localhost`, `*.localhost`,
`*.internal`, IPs loopback / privadas / link-local / unspecified, el endpoint de metadata
de cloud (`169.254.169.254`) y carrier-grade NAT (`100.64.0.0/10`). Las IPs literales se
comprueban directamente; los hostnames se resuelven y se comprueba **cada** dirección
devuelta.

Esto es solo defensa en profundidad. **El llamador (por ejemplo, el gateway de Laravel)
debe validar igualmente el objetivo antes de invocar `Scan`.**

## Licencia

MIT. Ver [LICENSE](LICENSE). Copyright (c) 2026 David Carrero Fernandez-Baillo.

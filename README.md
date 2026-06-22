# tlsscan

> English: [README.md](README.md) · Español: [README-es.md](README-es.md)

A dependency-free TLS configuration scanner written in Go. It uses **only the Go
standard library** (`crypto/tls`, `crypto/x509`, `net`, `encoding/json`), implements
the **SSL Labs Server Rating Guide** (a public specification), and contains **no GPL
code** — it is a clean MIT-licensed re-implementation of the *spec*, not of testssl.sh
or anyone else's code.

- **Module path:** `github.com/dcarrero/tlsscan`
- **License:** MIT (see [LICENSE](LICENSE))
- **Go:** 1.22+

It was born as the TLS engine of [HeaderForge](https://headerforge.io) but stands on
its own: a permissively licensed alternative to testssl.sh (which is GPLv2), meant to
be embedded in commercial products without license friction.

## Why it exists

- **Clean license.** testssl.sh is excellent but GPLv2; wrapping it in a commercial
  SaaS is legally murky. tlsscan is MIT: use it in whatever you like.
- **Zero dependencies.** Only Go's standard library. It does not reimplement
  cryptography: it performs real handshakes and observes what the server accepts.
- **Three faces, one engine.** Library, CLI and HTTP service all share the same
  `pkg/tlsscan` package.

## Three ways to use it

### 1. As a library

```go
import "github.com/dcarrero/tlsscan/pkg/tlsscan"

res, err := tlsscan.Scan(ctx, tlsscan.Options{
    Host:       "example.com",
    Port:       443,                 // default 443
    Timeout:    15 * time.Second,    // default 15s
    CheckVulns: true,                // run active vulnerability probes (slower)
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(res.Grade)          // e.g. "A+"
fmt.Println(res.Rating.Numeric) // 0-100
```

`Scan` returns a `*Result` whose JSON field names are a stable contract (consumed by
the HeaderForge gateway). See `pkg/tlsscan/types.go` for the full struct.

### 2. As a CLI (`cmd/tlsscan`)

```bash
go run ./cmd/tlsscan example.com
go run ./cmd/tlsscan -json -vulns badssl.com
```

Flags:

| Flag | Type | Default | Meaning |
|------|------|---------|---------|
| `-port` | int | `443` | Target port. |
| `-timeout` | duration | `15s` | Per-operation timeout (Go duration, e.g. `12s`, `1m`). |
| `-vulns` | bool | `false` | Run vulnerability probes (slower). |
| `-json` | bool | `false` | Output the JSON `Result` instead of human-readable text. |

The host is the single positional argument: `tlsscan [flags] <host>`.

### 3. As an HTTP service (`cmd/headerforge-tls`)

```bash
go run ./cmd/headerforge-tls
# Listens on 127.0.0.1:8081 by default. Override with TLS_SCAN_LISTEN.
TLS_SCAN_LISTEN=10.0.0.5:8081 go run ./cmd/headerforge-tls
```

Endpoints:

- `GET /healthz` → `200 ok`
- `POST /v1/scan` with a JSON body:

  ```json
  {
    "host": "example.com",
    "port": 443,
    "timeout_ms": 15000,
    "check_vulns": true
  }
  ```

  Returns the JSON `Result` on success, or `422` with `{"error": "..."}` if the scan
  could not run (e.g. the SSRF guard rejected the target).

The service binds to a private/loopback address by default and is meant to be reached
over a private network or reverse-proxied internally.

## Building

```bash
# Service binary
go build -o bin/headerforge-tls ./cmd/headerforge-tls

# CLI binary
go build -o bin/tlsscan ./cmd/tlsscan

# Static binary for any Linux (RunCloud, Stackscale): copy and run, no Go needed
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" \
  -o bin/headerforge-tls ./cmd/headerforge-tls
```

## What it detects

### Protocols

Each protocol version is probed with an **independent handshake** and the negotiated
version is verified against `ConnectionState` (defense in depth):

- **TLS 1.0, 1.1, 1.2, 1.3** — via Go's `crypto/tls`, one handshake pinned per version.
- **SSLv3** — Go won't negotiate it, so tlsscan sends a **hand-crafted SSLv3
  ClientHello** at the record layer and inspects the reply (feeds POODLE). No crypto
  is implemented; it only decides whether the server is willing to speak SSLv3.
- **ALPN / HTTP2** — detected from the negotiated protocol during certificate fetch.

### Certificate

The leaf certificate (and presented chain) is analysed for:

- **Validity by dates** (`not_before` / `not_after`) and days to expiry.
- **Hostname match** against the target host.
- **Self-signed** detection.
- **`chain_complete`** — the leaf is verified up to a **system-trusted root** using only
  the intermediates the server presented. Hostname is intentionally not checked in this
  step (reported separately), so a well-formed but wrong-host cert still counts as a
  complete chain. Missing intermediates or an unknown/self-signed root yield `false`.
- **Key type and bits** (RSA / ECDSA).
- **Signature algorithm**, with **SHA-1 distrust** (a SHA-1 signature flags the cert as
  distrusted).

### Ciphers

For each catalogued suite a TLS 1.2 handshake is attempted offering only that suite.
Accepted suites are classified **strong / weak / insecure**, and **forward secrecy** is
inferred from ECDHE/DHE key exchange.

### Vulnerabilities (`CheckVulns: true`)

- **Heartbleed (CVE-2014-0160)** — **active probe**: after a handshake it sends a
  malformed Heartbeat request claiming 16384 bytes of payload while sending one, and
  detects an oversized response (memory leak). Fails safe: any transport error is
  treated as not vulnerable. The leaked bytes are never inspected or stored.
- **POODLE** — inferred from SSLv3 being enabled (real SSLv3 probe).
- **DROWN** — inferred from SSLv2 being enabled (currently always `false`; see
  Limitations).
- **BEAST** — inferred from TLS 1.0 negotiated together with a CBC cipher suite.
- **SWEET32** — inferred from a 64-bit block cipher (3DES) being accepted.

## Rating

The grade follows the SSL Labs Server Rating Guide. The numeric score is a weighted
combination of three components:

| Component | Weight |
|-----------|--------|
| Protocol support | 30% |
| Key exchange | 30% |
| Cipher strength | 40% |

`numeric = (protocol*30 + keyExchange*30 + cipher*40) / 100`, then mapped to a letter
grade and adjusted by **grade caps**:

| Condition | Cap |
|-----------|-----|
| Certificate trust problem (invalid / self-signed / distrusted / hostname mismatch) | **T** |
| Critical vulnerability (Heartbleed, ROBOT, DROWN, insecure renegotiation) | **F** |
| SSLv2 enabled | **F** |
| SSLv3 enabled | **C** |
| No forward secrecy | **B** |
| Any insecure cipher | **C** |

A clean config with TLS 1.3, no weak/insecure ciphers and >30 days to expiry earns **A+**.

Every result includes the **ruleset version** so scans are reproducible. The current
constant is:

```
RulesetVersion = "ssllabs-rating-2009r"
```

## Testing

```bash
# Unit tests only (no network)
go test ./... -short

# badssl network suite — requires outbound internet access. Validates grading
# against badssl.com subdomains with known-bad TLS configurations.
go test ./... -run BadSSL
```

## Known limitations

tlsscan is honest about what is and isn't implemented. The following are present in the
`Result` schema (so the JSON contract is stable) but **always return `false`** today:

- **SSLv2 detection** — `ProbeSSL2` is a documented stub (SSLv2's 2-byte-header
  ClientHello is rare and risky to hand-craft against arbitrary servers). As a
  consequence, **DROWN** (which is inferred from SSLv2) also stays `false`.
- **ROBOT**
- **FREAK**
- **Logjam**
- **GoldenDoodle**
- **ZombiePoodle**
- **SleepingPoodle**
- **CVE-2019-1559** (zero-length padding oracle)
- **Insecure Renegotiation**
- **TLS_FALLBACK_SCSV** (missing-downgrade-protection detection)

These are wired as placeholders in `pkg/tlsscan/vulns.go` and `internal/vulns/` and will
be implemented as dedicated active probes.

## Security / SSRF note

A public scanner must never become a tool for reaching internal infrastructure. tlsscan
includes a **target guard** that refuses obviously internal destinations as defense in
depth: `localhost`, `*.localhost`, `*.internal`, loopback / private / link-local /
unspecified IPs, the cloud metadata endpoint (`169.254.169.254`) and carrier-grade NAT
(`100.64.0.0/10`). Literal IPs are checked directly; hostnames are resolved and **every**
returned address is checked.

This is defense in depth only. **The caller (e.g. the Laravel gateway) must still
validate the target before invoking `Scan`.**

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 David Carrero Fernandez-Baillo.

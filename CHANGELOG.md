# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-22

### Added

New **active, record/handshake-layer** probes. Each emits a hand-crafted
ClientHello (or SSLv2 CLIENT-HELLO) and interprets only the first bytes of the
reply. No cryptography is implemented and no handshake is ever completed. Every
probe is **fail-safe**: a timeout, reset, alert, or ambiguous response yields the
non-vulnerable / mitigation-present answer, never a false positive.

- **SSLv2 detection (DROWN, CVE-2016-0800).** `ProbeSSL2` now sends a real SSLv2
  CLIENT-HELLO (2-byte record header with the length MSB set, message type 0x01,
  version 0x0002, 3-byte cipher-specs incl. the export variants, challenge) and
  detects an SSLv2 SERVER-HELLO (type 0x04). Wired into the protocol probe; DROWN
  is derived from SSLv2 support. Capped to a short 4s window like the SSLv3 probe.
- **FREAK (CVE-2015-0204).** `ProbeExportRSA` offers ONLY RSA_EXPORT suites
  (0x0003 / 0x0008 / 0x0064 / 0x0062) in a TLS 1.0 ClientHello; a ServerHello
  reply means the server selected an export suite (vulnerable).
- **Logjam (CVE-2015-4000).** `ProbeExportDH` offers ONLY DHE_EXPORT suites
  (0x0014 / 0x0011); a ServerHello reply means vulnerable.
- **TLS_FALLBACK_SCSV (RFC 7507).** `ProbeFallbackSCSVMissing` sends a ClientHello
  pinned one version below the server's maximum, including the special
  FALLBACK_SCSV (0x5600) marker. A fatal `inappropriate_fallback` alert (level
  0x02, desc 0x56) means downgrade protection is **present** (`false`); a
  completed ServerHello at the lower version means it is **missing** (`true`).
  Only attempted when the server supports more than one protocol version.
- **Insecure renegotiation (RFC 5746).** `ProbeInsecureRenegotiation` sends a
  TLS 1.2 ClientHello advertising an empty `renegotiation_info` extension and
  parses the ServerHello: a server that does NOT echo `renegotiation_info`
  (0xff01) lacks secure-renegotiation support (`true`).
- **Rating caps.** Export ciphers (FREAK / Logjam) cap the grade to **C**
  (`export-cipher`). DROWN/SSLv2 and insecure renegotiation continue to cap to
  **F**. Heartbleed remains an active probe.

### Still deferred (intentionally always `false`)

ROBOT, GoldenDoodle, ZombiePoodle, SleepingPoodle and CVE-2019-1559 are
padding / Bleichenbacher-style oracles. Detecting them reliably requires
differential timing/response analysis across many crafted records, which carries
a high false-positive risk against load balancers, WAFs and tolerant TLS stacks.
They remain in the JSON contract but are not yet implemented.

## [0.1.1] - 2026-06-22

### Fixed
- **SSLv3 probe latency.** The legacy SSLv3 probe used the full scan timeout as its
  read deadline, so servers that silently ignore SSLv3 (the common case) blocked the
  whole scan for many seconds. The probe is now capped to a short 4s window
  (a server that speaks SSLv3 answers immediately; silence is treated as unsupported).

## [0.1.0] - 2026-06-22

First public release of the `github.com/dcarrero/tlsscan` module — a dependency-free,
MIT-licensed TLS configuration scanner that implements the SSL Labs Server Rating Guide
using only the Go standard library (no GPL code).

### Added

- **Protocol engine (TLS 1.0–1.3).** Each version is probed with an independent
  handshake and the negotiated version is verified against `ConnectionState`.
- **SSLv3 detection (POODLE).** Hand-crafted SSLv3 ClientHello at the record layer;
  no cryptography reimplemented. SSLv3 support feeds the POODLE inference.
- **Certificate analysis.** Validity by dates, hostname match, self-signed detection,
  key type/bits (RSA/ECDSA), signature algorithm, SHA-1 distrust, and `chain_complete`
  verification against the system trust store using the server-presented intermediates.
- **Cipher enumeration.** Per-suite TLS 1.2 handshakes classifying accepted suites as
  strong / weak / insecure, with forward secrecy inferred from ECDHE/DHE key exchange.
- **Heartbleed active probe (CVE-2014-0160).** Sends a malformed Heartbeat request and
  detects an oversized response (memory leak); fails safe on transport errors and never
  inspects the leaked bytes.
- **Inferred vulnerabilities.** POODLE (from SSLv3), DROWN (from SSLv2), BEAST
  (TLS 1.0 + CBC), and SWEET32 (3DES) derived from the protocol/cipher results.
- **SSL Labs rating.** Weighted score (protocol 30% / key exchange 30% / cipher 40%)
  mapped to a letter grade A+→F plus T/R, with grade caps: certificate trust → T,
  critical vulnerability or SSLv2 → F, SSLv3 → C, no forward secrecy → B, insecure
  cipher → C. Versioned ruleset (`ssllabs-rating-2009r`) for reproducible scans.
- **CLI (`cmd/tlsscan`).** Flags `-port`, `-timeout`, `-vulns`, `-json`; text or JSON
  output.
- **HTTP service (`cmd/headerforge-tls`).** `GET /healthz` and `POST /v1/scan`
  (`{host, port, timeout_ms, check_vulns}`); listens on `127.0.0.1:8081` by default,
  configurable via `TLS_SCAN_LISTEN`.
- **SSRF target guard.** Refuses internal hosts and private/reserved/loopback/link-local
  IPs, the cloud metadata endpoint, and carrier-grade NAT, resolving hostnames before
  checking.
- **badssl test suite.** Network tests (`go test ./... -run BadSSL`) validating grading
  against badssl.com subdomains, in addition to offline unit tests (`go test ./... -short`).

### Known limitations / Pending

The following are present in the `Result` schema (stable JSON contract) but currently
always return `false`; they will be implemented as dedicated active probes:

- **SSLv2 detection** — `ProbeSSL2` is a documented stub; consequently **DROWN** (inferred
  from SSLv2) also stays `false`.
- **ROBOT**
- **FREAK**
- **Logjam**
- **GoldenDoodle**
- **ZombiePoodle**
- **SleepingPoodle**
- **CVE-2019-1559** (zero-length padding oracle)
- **Insecure Renegotiation**
- **TLS_FALLBACK_SCSV** (missing downgrade-protection detection)

[Unreleased]: https://github.com/dcarrero/tlsscan/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dcarrero/tlsscan/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/dcarrero/tlsscan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dcarrero/tlsscan/releases/tag/v0.1.0

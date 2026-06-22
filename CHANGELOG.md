# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/dcarrero/tlsscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dcarrero/tlsscan/releases/tag/v0.1.0

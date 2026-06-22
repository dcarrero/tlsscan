package tlsscan

import (
	"context"

	"github.com/dcarrero/tlsscan/internal/handshake"
	"github.com/dcarrero/tlsscan/internal/vulns"
)

// probeVulnerabilities derives vulnerability status. Many flaws can be inferred
// from the protocol/cipher results already gathered (cheap); a few require
// active probes (Heartbleed, ROBOT) implemented in internal/vulns and wired in
// production. Inferred flaws are computed here from the Result so far.
//
// This is the layer where we can exceed testssl.sh, which documents that it
// does NOT yet cover GoldenDoodle, Sleeping/Zombie POODLE, CVE-2019-1559 and
// insecure renegotiation. Those active probes belong in internal/vulns.
func probeVulnerabilities(ctx context.Context, addr string, opts Options, r *Result) Vulnerabilities {
	v := Vulnerabilities{}

	// --- Inferred from configuration already collected ---

	// POODLE: SSLv3 enabled (now detectable via the raw SSLv3 ClientHello probe).
	v.Poodle = r.Protocols.SSL3
	// DROWN: SSLv2 enabled. SSLv2 detection is currently a documented stub, so
	// this stays false until ProbeSSL2 is implemented.
	v.Drown = r.Protocols.SSL2
	// BEAST: TLS 1.0 negotiated with at least one CBC cipher suite.
	v.Beast = r.Protocols.TLS10 && hasCBC(r.Ciphers)
	// SWEET32: a 64-bit block cipher (3DES) is accepted, regardless of how it
	// was classified.
	v.Sweet32 = has3DES(r.Ciphers)

	// --- Active probes ---
	// All of these are record/handshake-layer probes that interpret only the
	// first bytes of the server's reply. Each is FAIL-SAFE: timeout / reset /
	// alert / ambiguous response => not vulnerable (never a false positive).

	// Heartbleed (CVE-2014-0160): malformed Heartbeat + oversized response.
	if hb, err := vulns.Heartbleed(ctx, addr, opts.Timeout); err == nil {
		v.Heartbleed = hb
	}

	// FREAK (CVE-2015-0204): server willing to select an RSA_EXPORT suite.
	v.Freak = handshake.ProbeExportRSA(ctx, addr, opts.Timeout)

	// Logjam (CVE-2015-4000): server willing to select a DHE_EXPORT suite.
	v.Logjam = handshake.ProbeExportDH(ctx, addr, opts.Timeout)

	// Insecure renegotiation (RFC 5746): ServerHello omits renegotiation_info.
	v.InsecureRenegotiation = handshake.ProbeInsecureRenegotiation(ctx, addr, opts.Timeout)

	// TLS_FALLBACK_SCSV (RFC 7507): only meaningful when the server supports at
	// least two protocol versions, so we can attempt a real downgrade one
	// version below its maximum. If it supports a single version, downgrade
	// protection does not apply => not missing (false).
	if fb := fallbackProbeVersion(r.Protocols); fb != 0 {
		v.TLSFallbackSCSV = handshake.ProbeFallbackSCSVMissing(ctx, addr, fb, opts.Timeout)
	}

	// --- DEFERRED active probes (intentionally left false) ---
	// ROBOT, GoldenDoodle, ZombiePoodle, SleepingPoodle and CVE-2019-1559 are
	// all padding / Bleichenbacher-style oracles. Detecting them reliably
	// requires differential timing/response analysis across many crafted
	// records, which carries a high false-positive risk against load balancers,
	// WAFs and tolerant TLS stacks. Deferred: padding/Bleichenbacher oracle,
	// requires differential analysis, high false-positive risk.
	//   v.Robot                = false
	//   v.GoldenDoodle         = false
	//   v.ZombiePoodle         = false
	//   v.SleepingPoodle       = false
	//   v.ZeroLengthPaddingCVE = false

	return v
}

// fallbackProbeVersion returns a TLS version (on-the-wire value) strictly below
// the server's highest supported version, to be used as the pinned MaxVersion in
// the FALLBACK_SCSV downgrade probe. It returns 0 when the server supports only
// one version (or none), in which case the fallback probe does not apply.
//
// We never use TLS 1.3 as the fallback target: TLS 1.3 carries its supported
// version in an extension and downgrade protection there works differently, so
// the classic RFC 7507 alert is observed on TLS 1.2-and-below downgrades.
func fallbackProbeVersion(p Protocols) uint16 {
	// Collect supported versions from lowest to highest (wire values).
	const (
		wireTLS10 = 0x0301
		wireTLS11 = 0x0302
		wireTLS12 = 0x0303
	)
	var supported []uint16
	if p.TLS10 {
		supported = append(supported, wireTLS10)
	}
	if p.TLS11 {
		supported = append(supported, wireTLS11)
	}
	if p.TLS12 {
		supported = append(supported, wireTLS12)
	}
	// We need at least two distinct sub-1.3 versions to attempt a downgrade that
	// the FALLBACK_SCSV alert can fire on. If only TLS 1.3 plus a single lower
	// version exist, a downgrade from 1.3 to that version is also testable, so
	// count TLS 1.3 as raising the ceiling.
	highestSub13Count := len(supported)
	if highestSub13Count == 0 {
		return 0
	}
	if p.TLS13 {
		// Downgrade target is the highest sub-1.3 version (one below 1.3).
		return supported[highestSub13Count-1]
	}
	if highestSub13Count < 2 {
		return 0 // only a single sub-1.3 version and no 1.3 above it: no downgrade
	}
	// Target is one version below the highest sub-1.3 version.
	return supported[highestSub13Count-2]
}

func hasCBC(c CipherSummary) bool {
	return containsName(c.Strong, "CBC") || containsName(c.Weak, "CBC") || containsName(c.Insecure, "CBC")
}

func has3DES(c CipherSummary) bool {
	return containsName(c.Strong, "3DES") || containsName(c.Weak, "3DES") || containsName(c.Insecure, "3DES")
}

func containsName(list []string, substr string) bool {
	for _, n := range list {
		if len(substr) > 0 && indexOf(n, substr) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

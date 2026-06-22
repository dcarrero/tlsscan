package tlsscan

import (
	"context"

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
	// Heartbleed is fully implemented in internal/vulns. On any transport
	// error we treat the host as not vulnerable (fail safe) rather than
	// failing the whole scan.
	if hb, err := vulns.Heartbleed(ctx, addr, opts.Timeout); err == nil {
		v.Heartbleed = hb
	}

	// --- Remaining active probes (delegated; stubs in this skeleton) ---
	// v.Robot = vulns.Robot(ctx, addr, opts.Timeout)
	// v.Freak = vulns.Freak(ctx, addr, opts.Timeout)
	// v.Logjam = vulns.Logjam(ctx, addr, opts.Timeout)
	// v.GoldenDoodle = vulns.GoldenDoodle(ctx, addr, opts.Timeout)
	// v.ZombiePoodle = vulns.ZombiePoodle(ctx, addr, opts.Timeout)
	// v.SleepingPoodle = vulns.SleepingPoodle(ctx, addr, opts.Timeout)
	// v.ZeroLengthPaddingCVE = vulns.CVE20191559(ctx, addr, opts.Timeout)
	// v.InsecureRenegotiation = vulns.InsecureRenegotiation(ctx, addr, opts.Timeout)
	// v.TLSFallbackSCSV = vulns.FallbackSCSVMissing(ctx, addr, opts.Timeout)

	return v
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

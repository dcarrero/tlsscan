package tlsscan

import (
	"context"
	"testing"
	"time"
)

// These are NETWORK tests against the badssl.com test endpoints. They are
// skipped under `go test -short` and they t.Skipf on transport errors (DNS,
// resets, badssl.com flakiness) rather than failing, mirroring the heartbleed
// test pattern. They assert robust, environment-independent properties at the
// certificate and grade-cap level, never exact protocol support.

const badsslTimeout = 12 * time.Second

// scanBadSSL runs a scan against host, skipping the test on transport failure.
func scanBadSSL(t *testing.T, host string, checkVulns bool) *Result {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Scan(ctx, Options{
		Host:       host,
		Port:       443,
		Timeout:    badsslTimeout,
		CheckVulns: checkVulns,
	})
	if err != nil {
		t.Skipf("%s: scan transport error (network?): %v", host, err)
	}
	// A certificate fetch failure leaves an empty Certificate; treat as transport
	// flakiness and skip so we never assert on missing data.
	if res.Certificate.NotAfter.IsZero() {
		t.Skipf("%s: certificate not fetched (transport flakiness): %v", host, res.Errors)
	}
	return res
}

// hasTrustCap reports whether a trust-related grade cap was applied, either via
// the explicit "certificate-trust" cap or the resulting T grade.
func hasTrustCap(res *Result) bool {
	if res.Grade == GradeT {
		return true
	}
	for _, c := range res.GradeCaps {
		if c == "certificate-trust" {
			return true
		}
	}
	return false
}

func TestBadSSL_Expired(t *testing.T) {
	res := scanBadSSL(t, "expired.badssl.com", false)
	if res.Certificate.Valid {
		t.Errorf("expired.badssl.com: Certificate.Valid = true, want false")
	}
	if res.Certificate.DaysToExpiry >= 0 {
		t.Errorf("expired.badssl.com: DaysToExpiry = %d, want < 0", res.Certificate.DaysToExpiry)
	}
	if !hasTrustCap(res) {
		t.Errorf("expired.badssl.com: expected trust cap (T / certificate-trust); grade=%s caps=%v",
			res.Grade, res.GradeCaps)
	}
}

func TestBadSSL_SelfSigned(t *testing.T) {
	res := scanBadSSL(t, "self-signed.badssl.com", false)
	if !res.Certificate.SelfSigned {
		t.Errorf("self-signed.badssl.com: Certificate.SelfSigned = false, want true")
	}
	if !hasTrustCap(res) {
		t.Errorf("self-signed.badssl.com: expected trust cap; grade=%s caps=%v",
			res.Grade, res.GradeCaps)
	}
}

func TestBadSSL_WrongHost(t *testing.T) {
	res := scanBadSSL(t, "wrong.host.badssl.com", false)
	if res.Certificate.HostnameMatch {
		t.Errorf("wrong.host.badssl.com: Certificate.HostnameMatch = true, want false")
	}
	if !hasTrustCap(res) {
		t.Errorf("wrong.host.badssl.com: expected trust cap; grade=%s caps=%v",
			res.Grade, res.GradeCaps)
	}
}

// sha256.badssl.com is a known-good control: a valid, trusted, matching cert
// with a complete chain.
func TestBadSSL_GoodControl(t *testing.T) {
	res := scanBadSSL(t, "sha256.badssl.com", false)
	if !res.Certificate.Valid {
		t.Errorf("sha256.badssl.com: Certificate.Valid = false, want true")
	}
	if !res.Certificate.HostnameMatch {
		t.Errorf("sha256.badssl.com: Certificate.HostnameMatch = false, want true")
	}
	if !res.Certificate.ChainComplete {
		t.Errorf("sha256.badssl.com: Certificate.ChainComplete = false, want true")
	}
}

// 3des.badssl.com offers a 3DES (64-bit block) cipher; SWEET32 must be flagged
// and an insecure cipher must be present.
func TestBadSSL_3DES(t *testing.T) {
	res := scanBadSSL(t, "3des.badssl.com", true)
	if len(res.Ciphers.Insecure) == 0 {
		t.Errorf("3des.badssl.com: expected at least one insecure cipher, got none (strong=%v weak=%v)",
			res.Ciphers.Strong, res.Ciphers.Weak)
	}
	if !res.Vulnerabilities.Sweet32 {
		t.Errorf("3des.badssl.com: SWEET32 = false, want true (insecure=%v)", res.Ciphers.Insecure)
	}
}

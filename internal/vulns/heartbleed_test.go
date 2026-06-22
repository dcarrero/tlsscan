package vulns

import (
	"context"
	"testing"
	"time"
)

// TestHeartbleed_SafeServers verifies the probe reports NOT vulnerable against
// modern, patched servers. These are network tests; skip in CI without egress.
//
// For a positive control, run a deliberately vulnerable container locally:
//
//	docker run -p 8443:443 ghcr.io/some/heartbleed-vuln-openssl  (example)
//
// and assert Heartbleed returns true. Never point this probe at hosts you do
// not own or have permission to test.
func TestHeartbleed_SafeServers(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}

	safe := []string{
		"badssl.com:443",      // modern config, patched
		"www.google.com:443",  // patched
	}

	for _, addr := range safe {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			vuln, err := Heartbleed(ctx, addr, 10*time.Second)
			if err != nil {
				t.Skipf("transport error (network?): %v", err)
			}
			if vuln {
				t.Errorf("%s reported VULNERABLE to Heartbleed; expected safe", addr)
			}
		})
	}
}

// TestHeartbleed_TimeoutIsSafe ensures a non-responsive endpoint is treated as
// not-vulnerable rather than erroring out the whole scan.
func TestHeartbleed_TimeoutIsSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 198.51.100.0 is TEST-NET-2 (RFC 5737): routes nowhere, will time out.
	vuln, err := Heartbleed(ctx, "198.51.100.0:443", 1*time.Second)
	if vuln {
		t.Error("unreachable host should not be reported vulnerable")
	}
	_ = err // transport error is acceptable here
}

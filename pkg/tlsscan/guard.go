package tlsscan

import (
	"fmt"
	"net"
	"strings"
)

// guardTarget refuses obviously internal/private targets as defense in depth.
// The Laravel gateway must ALSO validate before calling, but a public scanner
// must never let itself be used to reach internal infrastructure (SSRF).
func guardTarget(host string) error {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return fmt.Errorf("empty host")
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".internal") {
		return fmt.Errorf("refusing internal host: %s", host)
	}

	// If host is a literal IP, check ranges directly.
	if ip := net.ParseIP(h); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("refusing private/reserved IP: %s", host)
		}
		return nil
	}

	// Resolve and check every returned address.
	ips, err := net.LookupIP(h)
	if err != nil {
		return fmt.Errorf("dns resolution failed: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("host resolves to blocked address: %s", ip.String())
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Cloud metadata endpoint.
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	// Carrier-grade NAT 100.64.0.0/10.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return true
	}
	return false
}

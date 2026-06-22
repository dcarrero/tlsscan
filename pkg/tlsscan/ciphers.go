package tlsscan

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// cipherCatalog maps Go's known cipher suite IDs to a strength class.
// "insecure" -> grade-capping; "weak" -> deductions; "strong" -> fine.
// Forward secrecy is inferred from ECDHE/DHE key exchange.
var cipherCatalog = map[uint16]struct {
	name     string
	class    string // strong | weak | insecure
	forwardS bool
}{
	tls.TLS_AES_128_GCM_SHA256:                  {"TLS_AES_128_GCM_SHA256", "strong", true},
	tls.TLS_AES_256_GCM_SHA384:                  {"TLS_AES_256_GCM_SHA384", "strong", true},
	tls.TLS_CHACHA20_POLY1305_SHA256:            {"TLS_CHACHA20_POLY1305_SHA256", "strong", true},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {"ECDHE_RSA_AES_128_GCM", "strong", true},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {"ECDHE_RSA_AES_256_GCM", "strong", true},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {"ECDHE_ECDSA_AES_128_GCM", "strong", true},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      {"ECDHE_RSA_AES_128_CBC_SHA", "weak", true},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {"RSA_AES_128_GCM", "weak", false},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            {"RSA_AES_128_CBC_SHA", "weak", false},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           {"RSA_3DES_EDE_CBC_SHA", "insecure", false}, // SWEET32
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          {"ECDHE_RSA_RC4_128_SHA", "insecure", true}, // RC4
}

// probeCiphers enumerates which catalogued ciphers the server accepts and
// whether forward secrecy is available. For each suite it attempts a TLS 1.2
// handshake offering only that suite.
func probeCiphers(ctx context.Context, addr string, opts Options) (CipherSummary, bool) {
	sum := CipherSummary{Strong: []string{}, Weak: []string{}, Insecure: []string{}}
	fs := false

	for id, meta := range cipherCatalog {
		if cipherAccepted(ctx, addr, opts, id) {
			switch meta.class {
			case "strong":
				sum.Strong = append(sum.Strong, meta.name)
			case "weak":
				sum.Weak = append(sum.Weak, meta.name)
			case "insecure":
				sum.Insecure = append(sum.Insecure, meta.name)
			}
			if meta.forwardS {
				fs = true
			}
		}
	}
	return sum, fs
}

func cipherAccepted(ctx context.Context, addr string, opts Options, suite uint16) bool {
	d := &net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	c := tls.Client(conn, &tls.Config{
		ServerName:         opts.Host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suite},
		InsecureSkipVerify: true,
	})
	return c.HandshakeContext(ctx) == nil
}

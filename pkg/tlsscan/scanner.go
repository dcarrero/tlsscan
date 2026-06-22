package tlsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dcarrero/tlsscan/internal/handshake"
)

// RulesetVersion identifies the rating spec implemented. Bump on rule changes.
const RulesetVersion = "ssllabs-rating-2009r"

// Scan probes the given host's TLS configuration and returns a graded Result.
// It uses only Go's standard library for modern protocols; legacy SSLv2/v3
// detection lives in the handshake subpackage (hand-crafted ClientHello).
//
// SSRF / abuse note: callers (the Laravel gateway) must validate that the host
// does not resolve to a private/internal address before invoking Scan. This
// library also refuses obviously internal targets as defense in depth.
func Scan(ctx context.Context, opts Options) (*Result, error) {
	start := time.Now()

	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}

	if err := guardTarget(opts.Host); err != nil {
		return nil, err
	}

	res := &Result{
		Host:           opts.Host,
		Port:           opts.Port,
		GradeCaps:      []string{},
		RulesetVersion: RulesetVersion,
		Errors:         []string{},
	}

	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))

	// 1. Probe each protocol version. Each probe is an independent handshake.
	res.Protocols = probeProtocols(ctx, addr, opts)

	// 2. Fetch and analyse the certificate chain via a TLS handshake.
	if chain, alpn, err := fetchCertificate(ctx, addr, opts); err != nil {
		res.Errors = append(res.Errors, "certificate: "+err.Error())
	} else {
		res.Certificate = analyseCertificate(chain, opts.Host)
		res.Protocols.ALPN = alpn
		res.Protocols.HTTP2 = contains(alpn, "h2")
	}

	// 3. Enumerate cipher suites and forward secrecy.
	res.Ciphers, res.ForwardSecrecy = probeCiphers(ctx, addr, opts)

	// 4. Vulnerability probes (optional, slower).
	if opts.CheckVulns {
		res.Vulnerabilities = probeVulnerabilities(ctx, addr, opts, res)
	}

	// 5. Compute the SSL Labs style rating and final grade.
	res.Rating, res.Grade, res.GradeCaps = rate(res)

	res.ScanDurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// probeProtocols attempts a handshake at each TLS version, recording support.
// SSLv2/v3 are delegated to legacy hand-crafted probes (see handshake pkg).
func probeProtocols(ctx context.Context, addr string, opts Options) Protocols {
	p := Protocols{}

	type vt struct {
		set func(bool)
		min uint16
		max uint16
	}
	versions := []vt{
		{func(b bool) { p.TLS10 = b }, tls.VersionTLS10, tls.VersionTLS10},
		{func(b bool) { p.TLS11 = b }, tls.VersionTLS11, tls.VersionTLS11},
		{func(b bool) { p.TLS12 = b }, tls.VersionTLS12, tls.VersionTLS12},
		{func(b bool) { p.TLS13 = b }, tls.VersionTLS13, tls.VersionTLS13},
	}

	for _, v := range versions {
		ok := handshakeAt(ctx, addr, opts, v.min, v.max)
		v.set(ok)
	}

	// Legacy protocols Go won't negotiate: probe with a raw, hand-crafted
	// ClientHello (record layer only, no crypto). SSLv3 detection feeds POODLE.
	// SSLv2 detection (DROWN) is a documented stub for now (see handshake pkg).
	p.SSL3 = handshake.ProbeSSL3(ctx, addr, opts.Timeout)
	p.SSL2 = handshake.ProbeSSL2(ctx, addr, opts.Timeout)

	return p
}

// handshakeAt returns true if a TLS handshake succeeds within [min,max].
func handshakeAt(ctx context.Context, addr string, opts Options, min, max uint16) bool {
	d := &net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	c := tls.Client(conn, &tls.Config{
		ServerName:         opts.Host,
		MinVersion:         min,
		MaxVersion:         max,
		InsecureSkipVerify: true, // we evaluate the cert ourselves, not trust it
	})
	err = c.HandshakeContext(ctx)
	// Defense in depth: confirm the negotiated version is exactly the one we
	// pinned. Since Min==Max, Go can only complete that version, but we verify
	// the ConnectionState rather than trust the handshake result alone.
	return err == nil && c.ConnectionState().Version == max
}

// fetchCertificate performs a handshake and returns the full peer certificate
// chain (leaf first, as sent by the server) and the negotiated ALPN protocols.
//
// Some servers (notably badssl.com) intermittently reset TLS 1.3 handshakes, so
// on a first failure we retry once with MaxVersion pinned to TLS 1.2.
func fetchCertificate(ctx context.Context, addr string, opts Options) ([]*x509.Certificate, []string, error) {
	chain, alpn, err := fetchCertificateAt(ctx, addr, opts, tls.VersionTLS13)
	if err != nil {
		// Retry once, capping at TLS 1.2 for servers that reset on TLS 1.3.
		chain, alpn, err = fetchCertificateAt(ctx, addr, opts, tls.VersionTLS12)
	}
	return chain, alpn, err
}

// fetchCertificateAt performs a single handshake with MaxVersion = maxVer.
func fetchCertificateAt(ctx context.Context, addr string, opts Options, maxVer uint16) ([]*x509.Certificate, []string, error) {
	d := &net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	c := tls.Client(conn, &tls.Config{
		ServerName:         opts.Host,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         maxVer,
		InsecureSkipVerify: true, // we evaluate the chain ourselves, not trust it
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("no peer certificate")
	}
	alpn := []string{}
	if state.NegotiatedProtocol != "" {
		alpn = append(alpn, state.NegotiatedProtocol)
	}
	return state.PeerCertificates, alpn, nil
}

// analyseCertificate extracts the fields we grade on from the peer chain
// (leaf first). chain must contain at least the leaf certificate.
func analyseCertificate(chain []*x509.Certificate, host string) Certificate {
	cert := chain[0]
	c := Certificate{
		Subject:       cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysToExpiry:  int(time.Until(cert.NotAfter).Hours() / 24),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		SANs:          cert.DNSNames,
	}

	now := time.Now()
	c.Valid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	c.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName
	c.HostnameMatch = cert.VerifyHostname(host) == nil
	c.ChainComplete = verifyChainComplete(chain)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		c.KeyType = "RSA"
		c.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		c.KeyType = "ECDSA"
		c.KeyBits = pub.Curve.Params().BitSize
	default:
		c.KeyType = "unknown"
	}

	// Distrust legacy Symantec PKI and SHA-1 signatures.
	if strings.Contains(strings.ToLower(c.SignatureAlgo), "sha1") {
		c.Distrusted = true
	}

	return c
}

// verifyChainComplete reports whether the leaf certificate can be verified up
// to a system-trusted root using only the intermediates the server presented.
// It builds an intermediates pool from chain[1:] and verifies against the
// system roots (Roots: nil). Hostname is intentionally not checked here
// (DNSName: "") so that a well-formed but wrong-host cert still counts as a
// complete chain; hostname matching is reported separately. A failure (e.g.
// missing intermediates, unknown/self-signed root) correctly yields false.
func verifyChainComplete(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         nil, // system trust store
		DNSName:       "",
	})
	return err == nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

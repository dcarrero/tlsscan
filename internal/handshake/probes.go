package handshake

// This file adds active, record-layer handshake probes that Go's crypto/tls
// cannot express directly because they require offering specific legacy/export
// cipher suites or the FALLBACK_SCSV / renegotiation_info signalling suites and
// then inspecting the raw ServerHello / Alert. Like the SSLv2/SSLv3 probes,
// these operate ONLY at the record and handshake-message layer: they emit a
// hand-crafted ClientHello and interpret the first bytes of the reply. No
// cryptography is implemented and no handshake is ever completed.
//
// Every probe is FAIL-SAFE: a timeout, reset, alert, or ambiguous reply yields
// the "not vulnerable" / "mitigation present" answer, never a false positive.
//
// License: MIT.

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

const (
	// TLS 1.0 version on the wire (record + ClientHello). Widely accepted as the
	// lowest common denominator for these legacy probes.
	versionTLS10 = 0x0301
	// TLS 1.1 version on the wire.
	versionTLS11 = 0x0302
	// TLS 1.2 version on the wire.
	versionTLS12 = 0x0303

	// Alert level / description for inappropriate_fallback (RFC 7507): a fatal
	// (level 0x02) alert with description 86 (0x56) means the server detected the
	// FALLBACK_SCSV and rejected the downgrade — i.e. the mitigation is present.
	alertLevelFatal              = 0x02
	alertInappropriateFallback   = 0x56
	extRenegotiationInfo         = 0xff01
	cipherFallbackSCSV    uint16 = 0x5600
)

// capTimeout mirrors the legacy probes: a server that supports a vector answers
// immediately; silence must not stall the whole scan.
func capTimeout(timeout time.Duration) time.Duration {
	if timeout > 4*time.Second {
		return 4 * time.Second
	}
	return timeout
}

// clientHelloTLS builds a ClientHello wrapped in a TLS record at recordVersion,
// advertising exactly the given cipher suites (each a 2-byte TLS suite id) and
// the supplied raw extensions block (may be nil/empty). clientVersion is the
// version put inside the ClientHello body; recordVersion is the outer record
// version. Null compression only.
func clientHelloTLS(recordVersion, clientVersion uint16, suites []uint16, extensions []byte) []byte {
	body := []byte{byte(clientVersion >> 8), byte(clientVersion)}
	// 32 bytes of random; zeros are fine for a probe.
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session_id length = 0

	// cipher_suites.
	sb := make([]byte, 0, len(suites)*2)
	for _, s := range suites {
		sb = append(sb, byte(s>>8), byte(s))
	}
	body = append(body, byte(len(sb)>>8), byte(len(sb)))
	body = append(body, sb...)

	// compression_methods: null only.
	body = append(body, 0x01, 0x00)

	// extensions (length-prefixed). Omitted entirely if empty, which matches a
	// classic TLS 1.0 ClientHello with no extensions.
	if len(extensions) > 0 {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
	}

	// Handshake header: type ClientHello (0x01) + 3-byte length.
	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	// Record header: handshake (0x16) + recordVersion + length.
	rec := make([]byte, 5+len(hs))
	rec[0] = recordHandshake
	binary.BigEndian.PutUint16(rec[1:3], recordVersion)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// readRecordHeader reads the 5-byte TLS record header and returns the content
// type, the record version, and the declared payload length.
func readRecordHeader(conn net.Conn) (contentType byte, version uint16, length int, err error) {
	header := make([]byte, 5)
	if _, err = readFull(conn, header); err != nil {
		return 0, 0, 0, err
	}
	return header[0], binary.BigEndian.Uint16(header[1:3]), int(binary.BigEndian.Uint16(header[3:5])), nil
}

// serverSelectsOffered sends helloBytes and reports whether the server replies
// with a ServerHello (handshake type 0x02) in a handshake record — meaning it
// accepted one of the cipher suites we offered. Any alert, reset, timeout, or
// non-handshake reply yields false (fail safe). This is the core of the FREAK
// and Logjam export-suite probes.
func serverSelectsOffered(ctx context.Context, addr string, timeout time.Duration, helloBytes []byte) bool {
	timeout = capTimeout(timeout)
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(helloBytes); err != nil {
		return false
	}

	contentType, _, recLen, err := readRecordHeader(conn)
	if err != nil {
		return false
	}
	// An alert means the server refused our (export-only) suites: not vulnerable.
	if contentType != recordHandshake || recLen < 1 {
		return false
	}
	first := make([]byte, 1)
	if _, err := readFull(conn, first); err != nil {
		return false
	}
	return first[0] == handshakeServerHello
}

// ProbeExportRSA reports whether the server is willing to negotiate an
// RSA_EXPORT cipher suite (FREAK, CVE-2015-0204). It offers ONLY the export RSA
// suites in a TLS 1.0 ClientHello; if the server answers with a ServerHello it
// selected one of them and is vulnerable.
func ProbeExportRSA(ctx context.Context, addr string, timeout time.Duration) bool {
	suites := []uint16{
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0064, // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
		0x0062, // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
	}
	hello := clientHelloTLS(versionTLS10, versionTLS10, suites, nil)
	return serverSelectsOffered(ctx, addr, timeout, hello)
}

// ProbeExportDH reports whether the server is willing to negotiate a
// DHE_EXPORT cipher suite (Logjam, CVE-2015-4000). It offers ONLY the export
// DHE suites in a TLS 1.0 ClientHello; a ServerHello reply means vulnerable.
func ProbeExportDH(ctx context.Context, addr string, timeout time.Duration) bool {
	suites := []uint16{
		0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	}
	hello := clientHelloTLS(versionTLS10, versionTLS10, suites, nil)
	return serverSelectsOffered(ctx, addr, timeout, hello)
}

// ProbeFallbackSCSVMissing reports whether the server FAILS to honour
// TLS_FALLBACK_SCSV (RFC 7507) — i.e. whether downgrade protection is MISSING.
//
// fallbackVersion must be a real version strictly below the server's highest
// supported version (the caller discovers this from the protocol probe). We send
// a ClientHello pinned to fallbackVersion that ALSO advertises the special
// FALLBACK_SCSV (0x5600) signalling suite. A server that implements the
// mitigation MUST reply with a fatal inappropriate_fallback alert (level 0x02,
// desc 0x56) => mitigation present => returns false. If instead it completes a
// ServerHello at the lower version, the mitigation is absent => returns true.
//
// Fail safe: timeout / reset / any ambiguous reply => false (do not claim the
// mitigation is missing without evidence).
func ProbeFallbackSCSVMissing(ctx context.Context, addr string, fallbackVersion uint16, timeout time.Duration) bool {
	timeout = capTimeout(timeout)
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Offer a broad set of common suites (so a real handshake could succeed) plus
	// the FALLBACK_SCSV marker, all pinned to the lower version.
	suites := []uint16{
		0xc02f, // ECDHE_RSA_AES_128_GCM_SHA256
		0xc030, // ECDHE_RSA_AES_256_GCM_SHA384
		0xc013, // ECDHE_RSA_AES_128_CBC_SHA
		0xc014, // ECDHE_RSA_AES_256_CBC_SHA
		0x002f, // RSA_AES_128_CBC_SHA
		0x0035, // RSA_AES_256_CBC_SHA
		0x000a, // RSA_3DES_EDE_CBC_SHA
		cipherFallbackSCSV,
	}
	hello := clientHelloTLS(fallbackVersion, fallbackVersion, suites, nil)
	if _, err := conn.Write(hello); err != nil {
		return false
	}

	contentType, _, recLen, err := readRecordHeader(conn)
	if err != nil {
		return false
	}

	if contentType == recordAlert {
		// Read the alert body (2 bytes: level, description).
		alert := make([]byte, 2)
		if recLen >= 2 {
			if _, err := readFull(conn, alert); err != nil {
				return false
			}
			if alert[0] == alertLevelFatal && alert[1] == alertInappropriateFallback {
				return false // mitigation PRESENT
			}
		}
		// Some other alert (e.g. handshake_failure): the downgrade was refused for
		// another reason. We cannot prove the mitigation is missing => fail safe.
		return false
	}

	if contentType == recordHandshake && recLen >= 1 {
		first := make([]byte, 1)
		if _, err := readFull(conn, first); err != nil {
			return false
		}
		// Server completed a ServerHello at the lower version without the fallback
		// alert => downgrade protection is MISSING.
		return first[0] == handshakeServerHello
	}

	return false
}

// ProbeInsecureRenegotiation reports whether the server lacks RFC 5746 secure
// renegotiation support.
//
// Under RFC 5746 a server includes renegotiation_info in its ServerHello ONLY
// if the client signalled support (either via the renegotiation_info extension
// or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff). So we MUST advertise
// support ourselves: we send a TLS 1.2 ClientHello carrying an empty
// renegotiation_info extension. Then we parse the ServerHello's extensions:
//   - server echoes renegotiation_info  => secure renegotiation supported => false
//   - server omits it                   => no RFC 5746 support             => true
//
// Fail safe: timeout / reset / alert / any parse ambiguity => false (we never
// claim a server is insecure without a clean ServerHello to inspect).
func ProbeInsecureRenegotiation(ctx context.Context, addr string, timeout time.Duration) bool {
	timeout = capTimeout(timeout)
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// A spread of common suites so a modern server completes the ServerHello.
	suites := []uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c, // ECDHE GCM (RSA + ECDSA)
		0xc013, 0xc014, // ECDHE CBC
		0x009c, 0x009d, // RSA GCM
		0x002f, 0x0035, // RSA CBC
	}
	// Advertise RFC 5746 support via an EMPTY renegotiation_info extension
	// (0xff01, ext length 1, renegotiated_connection length 0). This is what
	// makes the server's echo meaningful.
	renegExt := []byte{0xff, 0x01, 0x00, 0x01, 0x00}
	hello := clientHelloTLS(versionTLS12, versionTLS12, suites, renegExt)
	if _, err := conn.Write(hello); err != nil {
		return false
	}

	serverHello, err := readServerHelloMessage(conn)
	if err != nil || serverHello == nil {
		return false
	}
	return !serverHelloHasExtension(serverHello, extRenegotiationInfo)
}

// readServerHelloMessage reads TLS records until it has assembled the first
// handshake message and returns its raw bytes (handshake type + 3-byte length +
// body) if and only if that message is a ServerHello. Returns nil otherwise.
// It reads at most a couple of records — enough for any real ServerHello.
func readServerHelloMessage(conn net.Conn) ([]byte, error) {
	var buf []byte
	for len(buf) < 4 || len(buf) < 4+int(uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3])) {
		contentType, _, recLen, err := readRecordHeader(conn)
		if err != nil {
			return nil, err
		}
		if contentType != recordHandshake || recLen < 1 {
			return nil, nil // alert or unexpected record => fail safe
		}
		payload := make([]byte, recLen)
		if _, err := readFull(conn, payload); err != nil {
			return nil, err
		}
		buf = append(buf, payload...)
		// Guard against absurd lengths / runaway reads.
		if len(buf) > 1<<16 {
			break
		}
		if len(buf) >= 4 {
			msgLen := 4 + int(uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3]))
			if msgLen > 1<<16 {
				return nil, nil
			}
		}
	}
	if len(buf) < 4 || buf[0] != handshakeServerHello {
		return nil, nil
	}
	msgLen := 4 + int(uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3]))
	if msgLen > len(buf) {
		return nil, nil
	}
	return buf[:msgLen], nil
}

// serverHelloHasExtension walks a raw ServerHello handshake message (starting
// with the 1-byte type + 3-byte length) and reports whether it carries the
// given extension type. Returns false on any structural inconsistency.
func serverHelloHasExtension(msg []byte, wantExt uint16) bool {
	// Skip handshake header (4 bytes).
	p := 4
	// server_version (2) + random (32).
	p += 2 + 32
	if p+1 > len(msg) {
		return false
	}
	// session_id.
	sidLen := int(msg[p])
	p++
	p += sidLen
	// cipher_suite (2) + compression_method (1).
	p += 2 + 1
	if p > len(msg) {
		return false
	}
	// extensions are OPTIONAL in a ServerHello. If they are absent the server
	// did not include renegotiation_info => caller treats that as insecure.
	if p+2 > len(msg) {
		return false
	}
	extTotal := int(binary.BigEndian.Uint16(msg[p : p+2]))
	p += 2
	end := p + extTotal
	if end > len(msg) {
		end = len(msg)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(msg[p : p+2])
		elen := int(binary.BigEndian.Uint16(msg[p+2 : p+4]))
		p += 4
		if etype == wantExt {
			return true
		}
		p += elen
	}
	return false
}

// Package handshake contains hand-crafted, low-level TLS/SSL handshake probes
// for legacy protocol versions that Go's crypto/tls refuses to negotiate
// (SSLv2 and SSLv3). These probes operate purely at the record layer: they
// emit a minimal ClientHello and interpret only the first few bytes of the
// server's reply. They do NOT implement cryptography — they only decide whether
// the server is willing to speak the legacy protocol at all.
//
// Detecting SSLv3 is required for POODLE; SSLv2 for DROWN.
//
// License: MIT.
package handshake

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

const (
	// TLS/SSL record content types.
	recordHandshake = 0x16
	recordAlert     = 0x15

	// Handshake message types.
	handshakeServerHello = 0x02

	// SSL 3.0 version on the wire.
	versionSSL30 = 0x0300

	// SSLv2 message types (different framing from TLS; see ProbeSSL2).
	sslv2ClientHello = 0x01
	sslv2ServerHello = 0x04
)

// ProbeSSL3 reports whether the server accepts an SSLv3 handshake.
//
// It opens a raw TCP connection, sends a minimal SSLv3 ClientHello (record
// version 0x0300), and inspects the first bytes of the reply. The server is
// considered to support SSLv3 only if it answers with an SSLv3 handshake record
// (content type 0x16, record version 0x0300) carrying a ServerHello. A TLS
// alert, a connection reset, a timeout, or any non-SSLv3 record version is
// treated as "not supported" (fail safe).
func ProbeSSL3(ctx context.Context, addr string, timeout time.Duration) bool {
	// A server that speaks SSLv3 answers almost immediately; one that doesn't
	// often just stays silent, which would otherwise block the read for the full
	// scan timeout. Cap the legacy probe to a short window so it never dominates
	// the scan latency (fail-safe: silence => not supported).
	if timeout > 4*time.Second {
		timeout = 4 * time.Second
	}

	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(clientHelloSSL3()); err != nil {
		return false
	}

	// Read just the record header (5 bytes) plus the first handshake byte.
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		return false
	}

	contentType := header[0]
	recordVersion := binary.BigEndian.Uint16(header[1:3])
	recLen := int(binary.BigEndian.Uint16(header[3:5]))

	// An alert (e.g. handshake_failure / protocol_version) means refusal.
	if contentType == recordAlert {
		return false
	}
	// The server must reply with an SSLv3 handshake record.
	if contentType != recordHandshake || recordVersion != versionSSL30 || recLen < 1 {
		return false
	}

	// Peek the first handshake message byte: a ServerHello confirms the server
	// agreed to continue in SSLv3.
	first := make([]byte, 1)
	if _, err := readFull(conn, first); err != nil {
		return false
	}
	return first[0] == handshakeServerHello
}

// ProbeSSL2 reports whether the server speaks SSLv2 (the prerequisite for
// DROWN, CVE-2016-0800).
//
// SSLv2 does not use the modern 5-byte TLS record header. Instead it frames
// messages with a 2-byte (or 3-byte) header: in the common 2-byte form the
// high bit of the first byte is set and the remaining 15 bits are the record
// length. We send a real SSLv2 CLIENT-HELLO (message type 0x01, version
// 0x0002, a list of 3-byte cipher-specs and a challenge) and look for an
// SSLv2 SERVER-HELLO (message type 0x04) in the reply. Anything else — a TLS
// alert, a TLS record, a reset, a timeout, or an ambiguous response — is
// treated as "not supported" (fail safe), so we never raise a false DROWN.
//
// The probe is capped to a short window like ProbeSSL3: a server that speaks
// SSLv2 answers immediately; silence means it does not.
func ProbeSSL2(ctx context.Context, addr string, timeout time.Duration) bool {
	if timeout > 4*time.Second {
		timeout = 4 * time.Second
	}

	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(clientHelloSSL2()); err != nil {
		return false
	}

	// Read the 2-byte SSLv2 record header. In the 2-byte form the MSB of the
	// first byte is set; the low 15 bits are the record length.
	hdr := make([]byte, 2)
	if _, err := readFull(conn, hdr); err != nil {
		return false
	}

	// A modern TLS server confronted with SSLv2 bytes usually replies with a
	// TLS record: content type 0x15 (alert) or 0x16 (handshake) with the MSB
	// of the first byte clear. If the MSB is clear this is NOT an SSLv2 2-byte
	// record, so SSLv2 is not supported.
	if hdr[0]&0x80 == 0 {
		return false
	}

	recLen := int(hdr[0]&0x7f)<<8 | int(hdr[1])
	if recLen < 1 {
		return false
	}

	// Peek the first message byte: an SSLv2 SERVER-HELLO (0x04) confirms the
	// server agreed to speak SSLv2.
	first := make([]byte, 1)
	if _, err := readFull(conn, first); err != nil {
		return false
	}
	return first[0] == sslv2ServerHello
}

// clientHelloSSL2 builds a complete SSLv2 CLIENT-HELLO framed with the 2-byte
// SSLv2 record header (MSB of length set). It offers the classic SSLv2
// cipher-specs (3 bytes each, including the export 40-bit variants that DROWN
// abuses) and a 16-byte challenge.
func clientHelloSSL2() []byte {
	// SSLv2 cipher-specs are 3 bytes each (unlike TLS's 2-byte suites).
	cipherSpecs := []byte{
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
		0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	}
	challenge := make([]byte, 16) // zeros are fine: we never finish the handshake

	// CLIENT-HELLO message body (no SSLv2 record header yet).
	body := []byte{
		sslv2ClientHello, // message type: CLIENT-HELLO (0x01)
		0x00, 0x02,       // version: SSL 2.0
		byte(len(cipherSpecs) >> 8), byte(len(cipherSpecs)), // cipher-specs length
		0x00, 0x00, // session-id length = 0
		byte(len(challenge) >> 8), byte(len(challenge)), // challenge length
	}
	body = append(body, cipherSpecs...)
	body = append(body, challenge...)

	// SSLv2 2-byte record header: MSB of the first byte set, low 15 bits = length.
	rec := make([]byte, 2+len(body))
	rec[0] = 0x80 | byte(len(body)>>8)
	rec[1] = byte(len(body))
	copy(rec[2:], body)
	return rec
}

// clientHelloSSL3 builds a minimal, well-formed SSLv3 ClientHello wrapped in an
// SSLv3 record (record version 0x0300). It offers a small set of classic cipher
// suites and null compression. No extensions are sent (SSLv3 predates them).
func clientHelloSSL3() []byte {
	body := []byte{
		0x03, 0x00, // client_version: SSL 3.0
	}
	// 32 bytes of random (gmt_unix_time + random_bytes); zeros are acceptable
	// for a probe — we never complete the handshake.
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session_id length = 0

	// cipher_suites: a handful of suites an SSLv3 server is likely to offer.
	suites := []byte{
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x00, 0x05, // TLS_RSA_WITH_RC4_128_SHA
	}
	body = append(body, byte(len(suites)>>8), byte(len(suites)))
	body = append(body, suites...)

	// compression_methods: null only.
	body = append(body, 0x01, 0x00)

	// Prepend the handshake header (type ClientHello + 3-byte length).
	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // handshake type: ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	return wrapSSL3Record(recordHandshake, hs)
}

// wrapSSL3Record prepends an SSLv3 record header (type, version 0x0300, length).
func wrapSSL3Record(contentType byte, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = contentType
	binary.BigEndian.PutUint16(rec[1:3], versionSSL30)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(body)))
	copy(rec[5:], body)
	return rec
}

// readFull reads exactly len(buf) bytes or returns an error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

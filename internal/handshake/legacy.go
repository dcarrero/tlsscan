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

// ProbeSSL2 is a documented stub. Detecting SSLv2 (for DROWN) requires emitting
// the SSLv2-specific 2-byte-header ClientHello, which is both rare in the wild
// and risky to hand-craft against arbitrary servers. We deliberately return
// false until a dedicated, well-tested SSLv2 probe is implemented.
//
// TODO(tls): implement a real SSLv2 ClientHello probe (2-byte record header,
// MSB length, CLIENT-HELLO message type 0x01) and wire it into probeProtocols.
func ProbeSSL2(ctx context.Context, addr string, timeout time.Duration) bool {
	_ = ctx
	_ = addr
	_ = timeout
	return false
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

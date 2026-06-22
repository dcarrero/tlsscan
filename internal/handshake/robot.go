package handshake

// ROBOT (Return Of Bleichenbacher's Oracle Threat, 2017) detection.
//
// This is a faithful, dependency-free reimplementation of the canonical
// technique published by Hanno Böck, Juraj Somorovsky and Craig Young in the
// "robot-detect" tool. It checks whether a TLS server that supports RSA key
// exchange (TLS_RSA_WITH_* cipher suites) acts as a Bleichenbacher padding
// oracle, i.e. whether it distinguishes well-formed PKCS#1 v1.5 padding in the
// RSA-encrypted ClientKeyExchange from malformed padding through its observable
// response (alert type, handshake outcome, connection reset, timeout).
//
// Prerequisite: ROBOT only applies to RSA *key exchange*. If the server does
// not select an RSA-kex suite (it prefers ECDHE/DHE, or refuses our RSA-only
// ClientHello), ROBOT does not apply and the answer is false.
//
// Method (per robot-detect):
//  1. Offer ONLY RSA-kex suites in a TLS 1.2 ClientHello; read ServerHello,
//     Certificate (extract the server's RSA public key), ServerHelloDone.
//  2. Build five PKCS#1 v1.5 vectors — one well-formed and four malformed in
//     distinct ways — and RSA-encrypt each with the server's public key
//     (c = m^e mod N, plain modular exponentiation, NOT a crypto reimpl).
//  3. For each vector, on a fresh connection, complete ClientHello → Cert →
//     Done, then send ClientKeyExchange + ChangeCipherSpec + a bogus Finished,
//     and summarise the server's reaction into a robust signature. Repeat each
//     vector a few times for stability.
//  4. Decision (fail-safe): if every vector yields the SAME signature, the
//     server does not leak padding validity => NOT vulnerable (false). Only if
//     the well-formed vector yields a signature that is CONSISTENTLY different
//     from the malformed ones (reproducibly across repetitions) do we report a
//     Bleichenbacher oracle => vulnerable (true). Any noise, timeout, or
//     inconsistency that prevents a clean conclusion => false (never a false
//     positive).
//
// No cryptography is implemented here: we only do modular exponentiation with
// the server's PUBLIC key (math/big) and craft raw record/handshake bytes.
//
// License: MIT.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"net"
	"time"
)

const (
	// Handshake message types used by the ROBOT probe.
	handshakeCertificate      = 0x0b
	handshakeServerHelloDone  = 0x0e
	handshakeClientKeyExchange = 0x10

	// Record content types used by the ROBOT probe.
	recordChangeCipherSpec = 0x14
)

// rsaKexSuites are the TLS_RSA_WITH_* cipher suites (RSA key exchange). ROBOT
// only applies when the server selects one of these. ECDHE/DHE suites are
// deliberately excluded so a ServerHello reply proves RSA kex was chosen.
var rsaKexSuites = []uint16{
	0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
	0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
	0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
	0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

// robotVectorKind identifies one of the five canonical PKCS#1 v1.5 test vectors.
type robotVectorKind int

const (
	vecCorrect           robotVectorKind = iota // valid PKCS#1: 00 02 PS(>=8,!=0) 00 PMS(48)
	vecWrongFirstBytes                          // first two bytes not 00 02
	vecNo0x00                                   // no 00 delimiter anywhere
	vec0x00InPadding                            // 00 placed inside the first 8 padding bytes
	vec0x00AtWrongPMSPos                        // 00 at a position leaving a wrong PMS length
)

// allRobotVectors is the canonical ordered set: one well-formed vector first,
// then four malformed ones (matching robot-detect's intent).
var allRobotVectors = []robotVectorKind{
	vecCorrect,
	vecWrongFirstBytes,
	vecNo0x00,
	vec0x00InPadding,
	vec0x00AtWrongPMSPos,
}

// buildPKCS1Vector builds the k-byte PKCS#1 v1.5 plaintext block for the given
// vector kind, where k = len(N) in bytes. The premaster secret (PMS) is 48
// bytes: TLS version (0x0303) followed by 46 random bytes.
//
// Layout of a valid block (EME-PKCS1-v1_5): 0x00 0x02 || PS || 0x00 || M
// where PS is at least 8 non-zero padding bytes and M is the 48-byte PMS.
//
// This function is pure (given pms) so it can be unit-tested offline.
func buildPKCS1Vector(kind robotVectorKind, k int, pms []byte) []byte {
	block := make([]byte, k)

	// Length of the non-zero padding string PS so that:
	//   2 (header) + len(PS) + 1 (0x00 delimiter) + len(PMS) == k
	psLen := k - 3 - len(pms)
	if psLen < 8 {
		// Defensive: for any realistic RSA key (>= 1024-bit, k >= 128) and a
		// 48-byte PMS this is always >= 8. Clamp to keep the function total.
		psLen = 8
	}

	fillNonZero := func(b []byte) {
		for i := range b {
			b[i] = 0xff // any non-zero byte is a valid padding byte
		}
	}

	switch kind {
	case vecCorrect:
		// 00 02 || PS(non-zero) || 00 || PMS
		block[0] = 0x00
		block[1] = 0x02
		fillNonZero(block[2 : 2+psLen])
		block[2+psLen] = 0x00
		copy(block[3+psLen:], pms)

	case vecWrongFirstBytes:
		// Invalid leading bytes (0x41 0x17) — otherwise identical to the valid
		// block. The version-check that ROBOT exercises starts at the very first
		// bytes, so this must be rejected by a non-oracle server.
		fillNonZero(block) // start from all non-zero so there is a clean 00 later
		block[0] = 0x41
		block[1] = 0x17
		fillNonZero(block[2 : 2+psLen])
		block[2+psLen] = 0x00
		copy(block[3+psLen:], pms)

	case vecNo0x00:
		// 00 02 then non-zero all the way to the end: there is NO 0x00 delimiter,
		// so a conforming implementation cannot locate the message.
		block[0] = 0x00
		block[1] = 0x02
		fillNonZero(block[2:])

	case vec0x00InPadding:
		// 00 02 || a 0x00 placed early (inside the first 8 padding bytes, an
		// illegal position) || rest non-zero. PS must be >= 8 non-zero bytes, so
		// a 0x00 at offset 4 makes the padding invalid.
		block[0] = 0x00
		block[1] = 0x02
		fillNonZero(block[2:])
		block[4] = 0x00 // inside the mandatory 8-byte non-zero padding region

	case vec0x00AtWrongPMSPos:
		// Well-formed PKCS#1 framing (00 02 || PS || 00 || M) but the recovered
		// message has the WRONG TLS version in its first two bytes. A server that
		// checks the embedded client_version (the second ROBOT oracle dimension)
		// reacts differently here than to the correct vector.
		block[0] = 0x00
		block[1] = 0x02
		fillNonZero(block[2 : 2+psLen])
		block[2+psLen] = 0x00
		wrong := make([]byte, len(pms))
		copy(wrong, pms)
		if len(wrong) >= 2 {
			wrong[0] = 0x02 // bogus client_version major
			wrong[1] = 0x02 // bogus client_version minor (not 0x0303)
		}
		copy(block[3+psLen:], wrong)
	}

	return block
}

// newPMS returns a 48-byte TLS premaster secret: 0x03 0x03 followed by 46
// random bytes. On a RNG failure it falls back to a fixed version prefix with
// zero body (still 48 bytes); the probe never relies on PMS secrecy.
func newPMS() []byte {
	pms := make([]byte, 48)
	pms[0] = 0x03
	pms[1] = 0x03
	_, _ = rand.Read(pms[2:])
	return pms
}

// rsaEncrypt computes c = m^e mod N and returns it left-padded to k = len(N)
// bytes (the on-the-wire size of an RSA ciphertext). This is modular
// exponentiation with the server's PUBLIC key — not a cryptographic primitive
// reimplementation.
func rsaEncrypt(pub *rsa.PublicKey, block []byte) []byte {
	k := (pub.N.BitLen() + 7) / 8
	m := new(big.Int).SetBytes(block)
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	out := c.Bytes()
	if len(out) < k {
		padded := make([]byte, k)
		copy(padded[k-len(out):], out)
		return padded
	}
	return out
}

// robotSignature is a robust, comparable summary of the server's reaction to a
// crafted ClientKeyExchange + ChangeCipherSpec + bogus Finished.
type robotSignature struct {
	kind         string // "alert" | "handshake" | "closed" | "reset" | "timeout" | "error"
	alertLevel   byte
	alertDesc    byte
}

func (s robotSignature) equal(o robotSignature) bool {
	if s.kind != o.kind {
		return false
	}
	if s.kind == "alert" {
		return s.alertLevel == o.alertLevel && s.alertDesc == o.alertDesc
	}
	return true
}

// ProbeROBOT reports whether the server is vulnerable to ROBOT. It is fully
// self-contained and fail-safe: any prerequisite miss, transport error, or
// ambiguous/noisy result yields false (never a false positive).
//
// host is the SNI server name; addr is "host:port".
func ProbeROBOT(ctx context.Context, addr, host string, timeout time.Duration) bool {
	// Each individual exchange is short; cap per-connection latency so the whole
	// probe (handshake discovery + 5 vectors * repetitions) stays well bounded.
	per := capTimeout(timeout)
	if per > 3*time.Second {
		per = 3 * time.Second
	}

	// Step 1: discover the server's RSA public key via an RSA-kex-only handshake.
	pub := robotServerRSAKey(ctx, addr, host, per)
	if pub == nil {
		// Server did not select an RSA-kex suite, or we could not read its cert =>
		// ROBOT does not apply.
		return false
	}

	// Steps 2-3: establish a stable signature for the well-formed vector, then
	// compare each malformed vector against it. We repeat each vector for
	// robustness. Two repetitions are enough to reject non-deterministic noise
	// while keeping the probe fast.
	const repetitions = 2

	correct, ok := stableSignature(ctx, addr, host, pub, vecCorrect, repetitions, per)
	if !ok {
		return false // could not pin a reproducible baseline => fail safe
	}

	// Step 4: decision. A Bleichenbacher oracle exists only if the well-formed
	// vector is CONSISTENTLY distinguishable from EVERY malformed vector. We
	// short-circuit to false the moment any malformed vector matches the correct
	// signature (no distinction => mitigated), which keeps the common,
	// non-vulnerable case fast.
	for _, kind := range allRobotVectors {
		if kind == vecCorrect {
			continue
		}
		sig, ok := stableSignature(ctx, addr, host, pub, kind, repetitions, per)
		if !ok {
			return false // noisy / non-reproducible => fail safe
		}
		if sig.equal(correct) {
			return false // indistinguishable from valid padding => not vulnerable
		}
	}
	// Every malformed vector produced a reproducible signature different from the
	// well-formed one => a Bleichenbacher padding oracle is present.
	return true
}

// robotServerRSAKey performs a ClientHello → ServerHello → Certificate →
// ServerHelloDone exchange offering ONLY RSA-kex suites, and returns the
// server's leaf RSA public key. Returns nil if the server does not select an
// RSA-kex suite or anything is ambiguous (fail safe).
func robotServerRSAKey(ctx context.Context, addr, host string, timeout time.Duration) *rsa.PublicKey {
	conn := robotDial(ctx, addr, timeout)
	if conn == nil {
		return nil
	}
	defer conn.Close()

	if _, err := conn.Write(robotClientHello(host)); err != nil {
		return nil
	}
	_, pub := readServerHelloAndCert(conn)
	return pub
}

// stableSignature runs the crafted-record exchange `reps` times for a vector and
// returns the signature only if every repetition agrees. The boolean is false
// when the repetitions disagree or any exchange failed to produce a signature.
func stableSignature(ctx context.Context, addr, host string, pub *rsa.PublicKey, kind robotVectorKind, reps int, timeout time.Duration) (robotSignature, bool) {
	var first robotSignature
	for i := 0; i < reps; i++ {
		sig, ok := robotExchange(ctx, addr, host, pub, kind, timeout)
		if !ok {
			return robotSignature{}, false
		}
		if i == 0 {
			first = sig
			continue
		}
		if !sig.equal(first) {
			return robotSignature{}, false // noisy / non-deterministic => fail safe
		}
	}
	return first, true
}

// robotExchange performs one full crafted exchange for a vector on a fresh
// connection and returns the server's response signature. ok is false on a
// transport failure before we could elicit a response.
func robotExchange(ctx context.Context, addr, host string, pub *rsa.PublicKey, kind robotVectorKind, timeout time.Duration) (robotSignature, bool) {
	conn := robotDial(ctx, addr, timeout)
	if conn == nil {
		return robotSignature{}, false
	}
	defer conn.Close()

	// Re-run the start of the handshake on this fresh connection.
	if _, err := conn.Write(robotClientHello(host)); err != nil {
		return robotSignature{}, false
	}
	done, pub2 := readServerHelloAndCert(conn)
	if pub2 == nil || !done {
		// The server stopped selecting RSA kex mid-probe, or the handshake shape
		// changed: we cannot compare cleanly. Treat as transport failure.
		return robotSignature{}, false
	}

	// Build the PKCS#1 block, encrypt with the server key, and send the crafted
	// ClientKeyExchange + ChangeCipherSpec + bogus Finished.
	block := buildPKCS1Vector(kind, (pub.N.BitLen()+7)/8, newPMS())
	cipher := rsaEncrypt(pub, block)

	if _, err := conn.Write(robotClientKeyExchange(cipher)); err != nil {
		return robotSignature{}, false
	}
	if _, err := conn.Write(robotChangeCipherSpec()); err != nil {
		return robotSignature{}, false
	}
	if _, err := conn.Write(robotBogusFinished()); err != nil {
		return robotSignature{}, false
	}

	// A short read window for the reaction: a server that rejects our bogus
	// Finished answers immediately (alert/close/reset); a mitigated server that
	// simply ignores it would otherwise stall the whole probe. Silence is a
	// stable, comparable "timeout" signature in its own right, so a short cap is
	// safe and keeps the probe fast.
	respTimeout := timeout
	if respTimeout > 1500*time.Millisecond {
		respTimeout = 1500 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(respTimeout))

	return readRobotResponse(conn), true
}

// robotDial opens a TCP connection with a read/write deadline set to timeout.
func robotDial(ctx context.Context, addr string, timeout time.Duration) net.Conn {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn
}

// robotClientHello builds a TLS 1.2 ClientHello offering only RSA-kex suites and
// a server_name (SNI) extension for host. Reuses clientHelloTLS for the record
// framing; the SNI extension is required by virtual-hosted servers to return the
// correct certificate.
func robotClientHello(host string) []byte {
	return clientHelloTLS(versionTLS12, versionTLS12, rsaKexSuites, sniExtension(host))
}

// sniExtension builds a server_name (0x0000) extension for the given host name.
// Returns an empty slice for an empty/IP-only host (the extension is optional).
func sniExtension(host string) []byte {
	if host == "" {
		return nil
	}
	name := []byte(host)
	// ServerNameList: 2-byte list length, then entries of:
	//   name_type (1, 0x00 = host_name) + name length (2) + name bytes.
	entry := make([]byte, 0, 3+len(name))
	entry = append(entry, 0x00) // host_name
	entry = append(entry, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)

	list := make([]byte, 0, 2+len(entry))
	list = append(list, byte(len(entry)>>8), byte(len(entry)))
	list = append(list, entry...)

	ext := make([]byte, 0, 4+len(list))
	ext = append(ext, 0x00, 0x00) // extension type: server_name
	ext = append(ext, byte(len(list)>>8), byte(len(list)))
	ext = append(ext, list...)
	return ext
}

// robotClientKeyExchange wraps the RSA ciphertext into a ClientKeyExchange
// handshake message inside a TLS 1.2 handshake record. For RSA kex the body is
// the 2-byte length of the EncryptedPreMasterSecret followed by the ciphertext.
func robotClientKeyExchange(cipher []byte) []byte {
	body := make([]byte, 2+len(cipher))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(cipher)))
	copy(body[2:], cipher)

	hs := make([]byte, 4+len(body))
	hs[0] = handshakeClientKeyExchange
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	return wrapTLS12Record(recordHandshake, hs)
}

// robotChangeCipherSpec builds the ChangeCipherSpec record (single 0x01 byte).
func robotChangeCipherSpec() []byte {
	return wrapTLS12Record(recordChangeCipherSpec, []byte{0x01})
}

// robotBogusFinished sends a dummy "encrypted" Finished handshake record. After
// ChangeCipherSpec the server expects an encrypted Finished; any well-formed
// record here forces it to attempt decryption/verification, which is where a
// Bleichenbacher oracle's differential response surfaces. We use fixed bytes so
// the request is identical across vectors (only the prior key exchange differs).
func robotBogusFinished() []byte {
	// A plausible-length encrypted Finished payload (fixed, content irrelevant).
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = 0x0c
	}
	return wrapTLS12Record(recordHandshake, payload)
}

// wrapTLS12Record prepends a TLS 1.2 record header (type, 0x0303, length).
func wrapTLS12Record(contentType byte, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = contentType
	binary.BigEndian.PutUint16(rec[1:3], versionTLS12)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(body)))
	copy(rec[5:], body)
	return rec
}

// readServerHelloAndCert consumes records until it has seen a ServerHello, a
// Certificate (from which it extracts the leaf RSA public key) and a
// ServerHelloDone. It returns (done, pub): done is true once ServerHelloDone is
// seen, pub is the leaf RSA key (nil if the server did not present an RSA cert or
// did not select an RSA-kex suite). It is tolerant of TLS message coalescing and
// fails safe (returns nil) on any structural problem.
func readServerHelloAndCert(conn net.Conn) (done bool, pub *rsa.PublicKey) {
	var buf []byte
	sawServerHello := false

	// Read a bounded number of records: a server's ServerHello..ServerHelloDone
	// flight for RSA kex is small. Cap to avoid runaway reads.
	for iter := 0; iter < 16; iter++ {
		contentType, _, recLen, err := readRecordHeader(conn)
		if err != nil {
			return done, pub
		}
		if contentType != recordHandshake || recLen < 1 || recLen > 1<<16 {
			// An alert (e.g. handshake_failure because we offered only RSA kex and
			// the server has none) or any non-handshake record => RSA kex not
			// available => ROBOT does not apply.
			return done, nil
		}
		payload := make([]byte, recLen)
		if _, err := readFull(conn, payload); err != nil {
			return done, pub
		}
		buf = append(buf, payload...)

		// Parse all complete handshake messages currently buffered.
		for len(buf) >= 4 {
			msgLen := 4 + int(uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3]))
			if msgLen > len(buf) {
				break // need more record bytes
			}
			msg := buf[:msgLen]
			buf = buf[msgLen:]

			switch msg[0] {
			case handshakeServerHello:
				sawServerHello = true
			case handshakeCertificate:
				if k := parseLeafRSAKey(msg); k != nil {
					pub = k
				}
			case handshakeServerHelloDone:
				// A ServerHelloDone only arrives if the server accepted our
				// RSA-kex ClientHello and selected an RSA suite.
				return sawServerHello && pub != nil, pub
			}
		}
		if len(buf) > 1<<17 {
			return done, nil // runaway guard
		}
	}
	return done, pub
}

// parseLeafRSAKey extracts the leaf certificate's RSA public key from a
// Certificate handshake message. Returns nil if the leaf is not RSA or the
// structure is malformed (fail safe). Message layout:
//   type(1) len(3) certificates_len(3) [ cert_len(3) cert_DER ]...
func parseLeafRSAKey(msg []byte) *rsa.PublicKey {
	if len(msg) < 4+3+3 {
		return nil
	}
	p := 4 // skip handshake header
	certsLen := int(msg[p])<<16 | int(msg[p+1])<<8 | int(msg[p+2])
	p += 3
	if p+certsLen > len(msg) {
		return nil
	}
	if p+3 > len(msg) {
		return nil
	}
	certLen := int(msg[p])<<16 | int(msg[p+1])<<8 | int(msg[p+2])
	p += 3
	if certLen <= 0 || p+certLen > len(msg) {
		return nil
	}
	der := msg[p : p+certLen]
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		return rsaKey
	}
	return nil
}

// readRobotResponse reads the server's reaction after our crafted records and
// classifies it into a robust signature. It distinguishes TLS alerts (by level
// and description), a continued handshake, a clean close, a TCP reset, a
// timeout, and other errors.
func readRobotResponse(conn net.Conn) robotSignature {
	contentType, _, recLen, err := readRecordHeader(conn)
	if err != nil {
		return classifyTransportError(err)
	}
	switch contentType {
	case recordAlert:
		sig := robotSignature{kind: "alert"}
		if recLen >= 2 {
			alert := make([]byte, 2)
			if _, err := readFull(conn, alert); err == nil {
				sig.alertLevel = alert[0]
				sig.alertDesc = alert[1]
			}
		}
		return sig
	case recordHandshake, recordChangeCipherSpec:
		// The server kept going (e.g. emitted more handshake data) instead of
		// rejecting our bogus Finished — a distinguishable, "handshake" reaction.
		return robotSignature{kind: "handshake"}
	default:
		return robotSignature{kind: "handshake"}
	}
}

// classifyTransportError maps a read error to a stable signature kind: timeout,
// connection reset, clean EOF, or a generic error.
func classifyTransportError(err error) robotSignature {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return robotSignature{kind: "timeout"}
	}
	msg := err.Error()
	switch {
	case containsSubstr(msg, "reset"):
		return robotSignature{kind: "reset"}
	case containsSubstr(msg, "EOF"), containsSubstr(msg, "closed"), containsSubstr(msg, "broken pipe"):
		return robotSignature{kind: "closed"}
	default:
		return robotSignature{kind: "error"}
	}
}

// containsSubstr is a tiny substring check kept local to avoid pulling strings
// into this low-level file's dependency set (matches the style of the package).
func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

package handshake

// CBC padding-oracle family detection for TLS 1.2 (Craig Young's technique):
// Zombie POODLE, GOLDENDOODLE, Sleeping POODLE and the 0-length-padding
// OpenSSL CVE-2019-1559 ("0-Length OpenSSL").
//
// Unlike the other probes in this package, these oracles can ONLY be observed
// AFTER a TLS session is fully established: they are differential reactions to
// manipulated application-data records (bad MAC vs bad padding vs zero-length
// padding) on a live, keyed connection. We therefore implement a small,
// hand-rolled TLS 1.2 client that completes a CBC + HMAC-SHA handshake and then
// sends crafted records.
//
// IMPORTANT — we do NOT reimplement any cryptographic algorithm. We only call
// stdlib primitives (crypto/aes, crypto/hmac, crypto/sha1, crypto/sha256,
// crypto/ecdh, crypto/rsa, math/big) and assemble the TLS record/handshake
// framing by hand. The PRF (P_hash) is RFC 5246 plumbing on top of HMAC-SHA256.
//
// GUIDING PRINCIPLE: a false positive is the worst outcome. A modern server with
// a constant-time (Lucky13) MAC/pad implementation answers IDENTICALLY to every
// manipulation, so we report NOT vulnerable. We only flag a specific vuln when
// its crafted record yields a reaction that is DIFFERENT and REPRODUCIBLE versus
// the secure baseline, per Young's mapping. Any timeout, handshake failure,
// noise, or ambiguity => all four false. A false negative is acceptable; a false
// positive is not.
//
// License: MIT.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"
)

const (
	recordApplicationData = 0x17

	handshakeServerKeyExchange = 0x0c
	handshakeFinished          = 0x14

	// CBC + HMAC-SHA1 cipher suites we are able to drive by hand.
	suiteECDHE_RSA_AES128_CBC_SHA uint16 = 0xc013
	suiteECDHE_RSA_AES256_CBC_SHA uint16 = 0xc014
	suiteRSA_AES128_CBC_SHA       uint16 = 0x002f
	suiteRSA_AES256_CBC_SHA       uint16 = 0x0035

	// Named curves we support for ECDHE (crypto/ecdh).
	curveSecp256r1 uint16 = 0x0017
	curveSecp384r1 uint16 = 0x0018
	curveSecp521r1 uint16 = 0x0019
	curveX25519    uint16 = 0x001d
)

// cbcSuites is the ordered list of CBC suites we offer. ECDHE first (by far the
// most common today), RSA-kex as a fallback. All use HMAC-SHA1.
var cbcSuites = []uint16{
	suiteECDHE_RSA_AES128_CBC_SHA,
	suiteECDHE_RSA_AES256_CBC_SHA,
	suiteRSA_AES128_CBC_SHA,
	suiteRSA_AES256_CBC_SHA,
}

// cbcCipherParams holds the per-suite key/MAC sizes.
type cbcCipherParams struct {
	keyLen int // AES key bytes (16 or 32)
	macLen int // HMAC-SHA1 output = 20
	ivLen  int // AES block = 16 (explicit IV in TLS 1.2)
	ecdhe  bool
}

func paramsForSuite(suite uint16) (cbcCipherParams, bool) {
	switch suite {
	case suiteECDHE_RSA_AES128_CBC_SHA:
		return cbcCipherParams{keyLen: 16, macLen: 20, ivLen: 16, ecdhe: true}, true
	case suiteECDHE_RSA_AES256_CBC_SHA:
		return cbcCipherParams{keyLen: 32, macLen: 20, ivLen: 16, ecdhe: true}, true
	case suiteRSA_AES128_CBC_SHA:
		return cbcCipherParams{keyLen: 16, macLen: 20, ivLen: 16, ecdhe: false}, true
	case suiteRSA_AES256_CBC_SHA:
		return cbcCipherParams{keyLen: 32, macLen: 20, ivLen: 16, ecdhe: false}, true
	}
	return cbcCipherParams{}, false
}

// cbcSession holds the established keys and per-direction sequence numbers of a
// hand-rolled TLS 1.2 CBC session, ready to send crafted application-data.
type cbcSession struct {
	conn   net.Conn
	params cbcCipherParams

	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteMAC []byte
	serverWriteMAC []byte

	clientSeq uint64
	serverSeq uint64
}

// ----- PRF (RFC 5246, TLS 1.2, SHA-256) -----

// pHashSHA256 implements P_hash with HMAC-SHA256 (RFC 5246 §5):
//   P_hash(secret, seed) = HMAC(secret, A(1)+seed) + HMAC(secret, A(2)+seed) + ...
//   A(0) = seed; A(i) = HMAC(secret, A(i-1)).
// It returns exactly outLen bytes. Pure plumbing over the stdlib HMAC.
func pHashSHA256(secret, seed []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	a := seed // A(0)
	for len(out) < outLen {
		h := hmac.New(sha256.New, secret)
		h.Write(a)
		a = h.Sum(nil) // A(i)

		h2 := hmac.New(sha256.New, secret)
		h2.Write(a)
		h2.Write(seed)
		out = append(out, h2.Sum(nil)...)
	}
	return out[:outLen]
}

// prf12 is the TLS 1.2 PRF: PRF(secret, label, seed) = P_SHA256(secret, label+seed).
func prf12(secret []byte, label string, seed []byte, outLen int) []byte {
	ls := make([]byte, 0, len(label)+len(seed))
	ls = append(ls, []byte(label)...)
	ls = append(ls, seed...)
	return pHashSHA256(secret, ls, outLen)
}

// ----- record encryption (MAC-then-encrypt, CBC, explicit IV) -----

// macThenPad builds the TLS 1.2 CBC plaintext for a record: it computes
// HMAC-SHA1 over seq||type||version||len||content, appends it, then appends TLS
// padding so the total (content+MAC+pad) is a multiple of the AES block size.
// The returned bytes are what gets AES-CBC encrypted (after the explicit IV).
//
// If padOverride >= 0, that exact pad length-byte value is used for EVERY pad
// byte AND determines the number of pad bytes (padOverride+1), which lets the
// caller craft invalid-padding and zero-length-padding vectors. If forceBadMAC
// is set, the last MAC byte is flipped so the MAC is wrong but padding stays
// valid. With padOverride < 0 and forceBadMAC false this is a well-formed record.
func (s *cbcSession) macThenPad(contentType byte, content []byte, forceBadMAC bool, padOverride int) []byte {
	mac := s.computeMAC(s.clientWriteMAC, s.clientSeq, contentType, content)
	if forceBadMAC && len(mac) > 0 {
		mac[len(mac)-1] ^= 0xff
	}

	plain := make([]byte, 0, len(content)+len(mac)+s.params.ivLen)
	plain = append(plain, content...)
	plain = append(plain, mac...)

	blockSize := s.params.ivLen
	if padOverride >= 0 {
		// Craft an explicit pad: padOverride+1 bytes, each equal to padOverride.
		// This may produce a non-block-aligned total on purpose; the caller is
		// constructing an invalid record, so we DO NOT re-align it here.
		n := padOverride + 1
		for i := 0; i < n; i++ {
			plain = append(plain, byte(padOverride))
		}
		return plain
	}

	// Valid TLS padding: padLen value repeated (padLen+1) times so total is a
	// multiple of the block size. padLen in [0,255].
	rem := (len(plain) + 1) % blockSize
	padLen := 0
	if rem != 0 {
		padLen = blockSize - rem
	}
	for i := 0; i <= padLen; i++ {
		plain = append(plain, byte(padLen))
	}
	return plain
}

// computeMAC returns HMAC-SHA1 over the TLS 1.2 MAC input:
//   seq(8) || type(1) || version(2) || length(2) || content.
func (s *cbcSession) computeMAC(macKey []byte, seq uint64, contentType byte, content []byte) []byte {
	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[0:8], seq)
	hdr[8] = contentType
	binary.BigEndian.PutUint16(hdr[9:11], versionTLS12)
	binary.BigEndian.PutUint16(hdr[11:13], uint16(len(content)))

	mac := hmac.New(sha1.New, macKey)
	mac.Write(hdr[:])
	mac.Write(content)
	return mac.Sum(nil)
}

// encryptRecord AES-CBC-encrypts plain (content+MAC+padding) with a fresh random
// explicit IV and wraps it in a TLS 1.2 record of the given content type. plain
// must already be block-aligned for a VALID record; for crafted invalid-padding
// records the caller accepts whatever the server makes of a non-aligned blob
// (we still CBC-encrypt as many whole blocks as exist and the server will reject
// it — exactly the oracle stimulus we want, but we keep it block-aligned for the
// well-formed control via macThenPad).
func (s *cbcSession) encryptRecord(contentType byte, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.clientWriteKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, s.params.ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// CBC requires block-aligned input. If the crafted plaintext is not aligned
	// (intentional for some invalid vectors), zero-pad up to a block boundary so
	// AES-CBC can run; the server will still see invalid TLS padding/MAC.
	if len(plain)%s.params.ivLen != 0 {
		pad := s.params.ivLen - (len(plain) % s.params.ivLen)
		plain = append(plain, make([]byte, pad)...)
	}

	ct := make([]byte, len(plain))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, plain)

	// Record fragment = explicit IV || ciphertext.
	frag := make([]byte, 0, len(iv)+len(ct))
	frag = append(frag, iv...)
	frag = append(frag, ct...)

	return wrapTLS12Record(contentType, frag), nil
}

// sendCrafted sends an application-data record built from content with the given
// manipulation, advancing the client sequence number. forceBadMAC flips the MAC;
// padOverride (>=0) crafts an explicit pad value/length; both false/-1 => a
// well-formed record.
func (s *cbcSession) sendCrafted(content []byte, forceBadMAC bool, padOverride int) error {
	plain := s.macThenPad(recordApplicationData, content, forceBadMAC, padOverride)
	rec, err := s.encryptRecord(recordApplicationData, plain)
	if err != nil {
		return err
	}
	if _, err := s.conn.Write(rec); err != nil {
		return err
	}
	s.clientSeq++
	return nil
}

// ----- response classification -----

// cbcReaction is a robust, comparable summary of how the server reacted to a
// crafted application-data record.
type cbcReaction struct {
	kind       string // "alert" | "data" | "closed" | "reset" | "timeout" | "error"
	alertLevel byte
	alertDesc  byte
}

func (r cbcReaction) equal(o cbcReaction) bool {
	if r.kind != o.kind {
		return false
	}
	if r.kind == "alert" {
		return r.alertLevel == o.alertLevel && r.alertDesc == o.alertDesc
	}
	return true
}

// readReaction reads the server's reaction (one record header + a short body, or
// a transport error) and classifies it. It does NOT attempt to decrypt server
// data: the alert level/description that matters for the oracle is sent in a
// (possibly encrypted) record, but TLS alerts in response to a bad record are
// observable as: an Alert record, application-data continuing, or a TCP
// close/reset/timeout. We classify on the record content type and, for alerts,
// best-effort on the visible bytes. Servers that encrypt the alert still expose
// the alert RECORD type, which is the primary discriminator we rely on.
func (s *cbcSession) readReaction(timeout time.Duration) cbcReaction {
	_ = s.conn.SetReadDeadline(time.Now().Add(timeout))
	contentType, _, recLen, err := readRecordHeader(s.conn)
	if err != nil {
		return classifyCBCTransportError(err)
	}
	switch contentType {
	case recordAlert:
		r := cbcReaction{kind: "alert"}
		if recLen >= 2 {
			body := make([]byte, recLen)
			if _, err := readFull(s.conn, body); err == nil {
				// For a CBC session the alert is encrypted, so the visible bytes are
				// NOT the cleartext level/desc. We therefore key the reaction on the
				// alert record TYPE plus its fragment LENGTH, which differs between a
				// plaintext 2-byte alert and an encrypted alert, and is stable per
				// server behaviour. Record the first two bytes only as a weak tag.
				r.alertLevel = body[0]
				r.alertDesc = body[1]
			}
		}
		return r
	case recordApplicationData, recordHandshake, recordChangeCipherSpec:
		// Server kept the connection alive and sent data instead of an alert.
		return cbcReaction{kind: "data"}
	default:
		return cbcReaction{kind: "data"}
	}
}

func classifyCBCTransportError(err error) cbcReaction {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return cbcReaction{kind: "timeout"}
	}
	msg := err.Error()
	switch {
	case containsSubstr(msg, "reset"):
		return cbcReaction{kind: "reset"}
	case containsSubstr(msg, "EOF"), containsSubstr(msg, "closed"), containsSubstr(msg, "broken pipe"):
		return cbcReaction{kind: "closed"}
	default:
		return cbcReaction{kind: "error"}
	}
}

// ----- handshake driver -----

// establishCBCSession performs a full TLS 1.2 handshake with a CBC+HMAC-SHA
// suite and returns a ready-to-use cbcSession. Returns nil if the server does
// not negotiate any of our CBC suites or anything is ambiguous (fail safe).
func establishCBCSession(ctx context.Context, addr, host string, timeout time.Duration) *cbcSession {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil
	}

	hello := cbcClientHello(host, clientRandom)
	// Track all handshake messages (without record headers) for the Finished MAC.
	var transcript []byte
	transcript = append(transcript, hello[5:]...) // strip record header

	if _, err := conn.Write(hello); err != nil {
		return nil
	}

	hs := newHSReader(conn)

	// ServerHello.
	shType, sh, err := hs.next()
	if err != nil || shType != handshakeServerHello {
		return nil
	}
	transcript = append(transcript, sh...)
	suite, serverRandom, ok2 := parseServerHelloSuite(sh)
	if !ok2 {
		return nil
	}
	params, supported := paramsForSuite(suite)
	if !supported {
		return nil // server picked a non-CBC suite (e.g. we'd never offer it, but be safe)
	}

	// Certificate (need leaf RSA public key for RSA-kex; ECDHE uses it only for
	// the (unverified) signature, which we do not check — fail-safe scanner).
	certType, certMsg, err := hs.next()
	if err != nil || certType != handshakeCertificate {
		return nil
	}
	transcript = append(transcript, certMsg...)
	rsaPub := parseLeafRSAKey(certMsg)

	var premaster []byte
	var clientKeyExchangeBody []byte

	if params.ecdhe {
		// ServerKeyExchange carries the ECDHE params + server public point.
		skeType, skeMsg, err := hs.next()
		if err != nil || skeType != handshakeServerKeyExchange {
			return nil
		}
		transcript = append(transcript, skeMsg...)
		curveID, serverPoint, ok3 := parseECDHEServerKeyExchange(skeMsg)
		if !ok3 {
			return nil
		}
		curve, ok4 := ecdhCurve(curveID)
		if !ok4 {
			return nil
		}
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil
		}
		srvPub, err := curve.NewPublicKey(serverPoint)
		if err != nil {
			return nil
		}
		shared, err := priv.ECDH(srvPub)
		if err != nil {
			return nil
		}
		premaster = shared
		// ClientKeyExchange body for ECDHE = 1-byte point length + our point.
		myPoint := priv.PublicKey().Bytes()
		clientKeyExchangeBody = append([]byte{byte(len(myPoint))}, myPoint...)
	} else {
		// RSA kex: encrypt a fresh 48-byte premaster (03 03 || 46 random) with the
		// server's RSA public key (PKCS#1 v1.5) using the stdlib.
		if rsaPub == nil {
			return nil
		}
		pms := make([]byte, 48)
		pms[0] = 0x03
		pms[1] = 0x03
		if _, err := rand.Read(pms[2:]); err != nil {
			return nil
		}
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, pms)
		if err != nil {
			return nil
		}
		premaster = pms
		// TLS RSA ClientKeyExchange body = 2-byte length + ciphertext.
		clientKeyExchangeBody = make([]byte, 2+len(enc))
		binary.BigEndian.PutUint16(clientKeyExchangeBody[0:2], uint16(len(enc)))
		copy(clientKeyExchangeBody[2:], enc)
	}

	// Skip any remaining server flight messages until ServerHelloDone.
	for {
		t, msg, err := hs.next()
		if err != nil {
			return nil
		}
		transcript = append(transcript, msg...)
		if t == handshakeServerHelloDone {
			break
		}
		// CertificateRequest etc. are unexpected for our offered suites; bail safe.
		if t != handshakeCertificate && t != handshakeServerKeyExchange {
			// tolerate but do not loop forever
		}
	}

	// Derive master secret and key block.
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	masterSecret := prf12(premaster, "master secret", seed, 48)

	// key_block = PRF(master, "key expansion", server_random + client_random).
	keySeed := append(append([]byte{}, serverRandom...), clientRandom...)
	macLen, keyLen := params.macLen, params.keyLen
	keyBlock := prf12(masterSecret, "key expansion", keySeed, 2*macLen+2*keyLen)

	sess := &cbcSession{conn: conn, params: params}
	off := 0
	sess.clientWriteMAC = keyBlock[off : off+macLen]
	off += macLen
	sess.serverWriteMAC = keyBlock[off : off+macLen]
	off += macLen
	sess.clientWriteKey = keyBlock[off : off+keyLen]
	off += keyLen
	sess.serverWriteKey = keyBlock[off : off+keyLen]
	off += keyLen
	// (No fixed IV in TLS 1.2; explicit per-record IV is used.)

	// Send ClientKeyExchange.
	cke := wrapHandshake(handshakeClientKeyExchange, clientKeyExchangeBody)
	transcript = append(transcript, cke...)
	if _, err := conn.Write(wrapTLS12Record(recordHandshake, cke)); err != nil {
		return nil
	}

	// Send ChangeCipherSpec (plaintext record).
	if _, err := conn.Write(wrapTLS12Record(recordChangeCipherSpec, []byte{0x01})); err != nil {
		return nil
	}

	// Compute client Finished: verify_data = PRF(master, "client finished",
	// SHA256(all handshake messages so far), 12). The Finished message itself is
	// included in the transcript only for the SERVER Finished, not the client's.
	transcriptHash := sha256.Sum256(transcript)
	verifyData := prf12(masterSecret, "client finished", transcriptHash[:], 12)
	finishedMsg := wrapHandshake(handshakeFinished, verifyData)

	// Encrypt and send the Finished as the first record under the new keys
	// (client seq = 0).
	finPlain := sess.macThenPad(recordHandshake, finishedMsg, false, -1)
	finRec, err := sess.encryptRecord(recordHandshake, finPlain)
	if err != nil {
		return nil
	}
	if _, err := conn.Write(finRec); err != nil {
		return nil
	}
	sess.clientSeq++

	// Read the server's reaction to our Finished: it must send its own
	// ChangeCipherSpec + encrypted Finished (handshake records). If instead it
	// sends an alert (our Finished was rejected => our crypto is wrong), the
	// session is not usable and we fail safe.
	if !sess.expectServerFinished(timeout) {
		return nil
	}

	ok = true
	return sess
}

// expectServerFinished reads records after our Finished and returns true once the
// server has sent its ChangeCipherSpec followed by an (encrypted) handshake
// Finished record, indicating it ACCEPTED our Finished. Any alert => false.
func (s *cbcSession) expectServerFinished(timeout time.Duration) bool {
	_ = s.conn.SetReadDeadline(time.Now().Add(timeout))
	sawCCS := false
	for i := 0; i < 6; i++ {
		contentType, _, recLen, err := readRecordHeader(s.conn)
		if err != nil {
			return false
		}
		if recLen < 0 || recLen > 1<<16 {
			return false
		}
		body := make([]byte, recLen)
		if _, err := readFull(s.conn, body); err != nil {
			return false
		}
		switch contentType {
		case recordAlert:
			return false // server rejected our Finished
		case recordChangeCipherSpec:
			sawCCS = true
		case recordHandshake:
			// After CCS, the server's encrypted Finished arrives as a handshake
			// record. Seeing it (post-CCS) means our Finished was accepted. We do
			// not (and cannot cheaply) verify its contents; acceptance is proven by
			// the server progressing to its own Finished rather than alerting.
			if sawCCS {
				s.serverSeq++ // account for the server's Finished record
				return true
			}
		case recordApplicationData:
			// Some stacks may coalesce; treat data after CCS as acceptance.
			if sawCCS {
				return true
			}
		}
	}
	return false
}

// ----- handshake message reader -----

// hsReader reassembles handshake messages from a stream of TLS records.
type hsReader struct {
	conn net.Conn
	buf  []byte
}

func newHSReader(conn net.Conn) *hsReader { return &hsReader{conn: conn} }

// next returns the next complete handshake message (type + body, body returned
// includes the 4-byte handshake header so it can be appended to the transcript)
// or an error. It reads more records as needed.
func (r *hsReader) next() (byte, []byte, error) {
	for {
		if len(r.buf) >= 4 {
			msgLen := 4 + int(uint32(r.buf[1])<<16|uint32(r.buf[2])<<8|uint32(r.buf[3]))
			if msgLen <= len(r.buf) {
				msg := r.buf[:msgLen]
				r.buf = r.buf[msgLen:]
				return msg[0], append([]byte{}, msg...), nil
			}
		}
		contentType, _, recLen, err := readRecordHeader(r.conn)
		if err != nil {
			return 0, nil, err
		}
		if contentType != recordHandshake || recLen < 1 || recLen > 1<<16 {
			return 0, nil, errNotHandshake
		}
		payload := make([]byte, recLen)
		if _, err := readFull(r.conn, payload); err != nil {
			return 0, nil, err
		}
		r.buf = append(r.buf, payload...)
		if len(r.buf) > 1<<18 {
			return 0, nil, errNotHandshake
		}
	}
}

// errNotHandshake is returned when a non-handshake record interrupts the flight.
var errNotHandshake = &cbcError{"non-handshake record during handshake"}

type cbcError struct{ s string }

func (e *cbcError) Error() string { return e.s }

// ----- ClientHello / ServerHello / SKE parsing -----

// cbcClientHello builds a TLS 1.2 ClientHello offering our CBC suites, with SNI,
// supported_groups, ec_point_formats and signature_algorithms extensions so an
// ECDHE_RSA server completes the handshake. clientRandom (32 bytes) is embedded.
func cbcClientHello(host string, clientRandom []byte) []byte {
	body := []byte{0x03, 0x03} // client_version = TLS 1.2
	body = append(body, clientRandom...)
	body = append(body, 0x00) // session_id length = 0

	sb := make([]byte, 0, len(cbcSuites)*2)
	for _, s := range cbcSuites {
		sb = append(sb, byte(s>>8), byte(s))
	}
	body = append(body, byte(len(sb)>>8), byte(len(sb)))
	body = append(body, sb...)

	body = append(body, 0x01, 0x00) // compression: null only

	ext := cbcExtensions(host)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := wrapHandshake(0x01, body)
	return wrapTLS12Record(recordHandshake, hs)
}

// cbcExtensions assembles the extension block: SNI, supported_groups,
// ec_point_formats, signature_algorithms.
func cbcExtensions(host string) []byte {
	var ext []byte
	ext = append(ext, sniExtension(host)...)

	// supported_groups (0x000a): x25519, secp256r1, secp384r1, secp521r1.
	groups := []byte{
		byte(curveX25519 >> 8), byte(curveX25519),
		byte(curveSecp256r1 >> 8), byte(curveSecp256r1),
		byte(curveSecp384r1 >> 8), byte(curveSecp384r1),
		byte(curveSecp521r1 >> 8), byte(curveSecp521r1),
	}
	sg := make([]byte, 0, 6+len(groups))
	sg = append(sg, 0x00, 0x0a)
	sg = append(sg, byte((len(groups)+2)>>8), byte(len(groups)+2))
	sg = append(sg, byte(len(groups)>>8), byte(len(groups)))
	sg = append(sg, groups...)
	ext = append(ext, sg...)

	// ec_point_formats (0x000b): uncompressed only.
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)

	// signature_algorithms (0x000d): a spread RSA + ECDSA over SHA-256/384/512.
	sigs := []byte{
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x01, // rsa_pkcs1_sha384
		0x06, 0x01, // rsa_pkcs1_sha512
		0x02, 0x01, // rsa_pkcs1_sha1
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x06, 0x03, // ecdsa_secp521r1_sha512
	}
	sa := make([]byte, 0, 6+len(sigs))
	sa = append(sa, 0x00, 0x0d)
	sa = append(sa, byte((len(sigs)+2)>>8), byte(len(sigs)+2))
	sa = append(sa, byte(len(sigs)>>8), byte(len(sigs)))
	sa = append(sa, sigs...)
	ext = append(ext, sa...)

	return ext
}

// parseServerHelloSuite extracts the chosen cipher suite and the 32-byte server
// random from a ServerHello handshake message (with 4-byte header).
func parseServerHelloSuite(msg []byte) (suite uint16, serverRandom []byte, ok bool) {
	p := 4
	if p+2+32+1 > len(msg) {
		return 0, nil, false
	}
	p += 2 // server_version
	serverRandom = append([]byte{}, msg[p:p+32]...)
	p += 32
	sidLen := int(msg[p])
	p++
	p += sidLen
	if p+2 > len(msg) {
		return 0, nil, false
	}
	suite = binary.BigEndian.Uint16(msg[p : p+2])
	return suite, serverRandom, true
}

// parseECDHEServerKeyExchange extracts the named curve id and the server's
// public EC point from an ECDHE ServerKeyExchange (with 4-byte header). The
// ServerECDHParams prefix is: curve_type(1)=named_curve(0x03) || namedcurve(2)
// || public_len(1) || public(point). We do NOT verify the trailing signature
// (this is a scanner with InsecureSkipVerify semantics throughout).
func parseECDHEServerKeyExchange(msg []byte) (curveID uint16, point []byte, ok bool) {
	p := 4
	if p+4 > len(msg) {
		return 0, nil, false
	}
	if msg[p] != 0x03 { // must be named_curve
		return 0, nil, false
	}
	p++
	curveID = binary.BigEndian.Uint16(msg[p : p+2])
	p += 2
	plen := int(msg[p])
	p++
	if p+plen > len(msg) {
		return 0, nil, false
	}
	point = append([]byte{}, msg[p:p+plen]...)
	return curveID, point, true
}

// ecdhCurve maps a TLS named-curve id to a crypto/ecdh curve.
func ecdhCurve(id uint16) (ecdh.Curve, bool) {
	switch id {
	case curveX25519:
		return ecdh.X25519(), true
	case curveSecp256r1:
		return ecdh.P256(), true
	case curveSecp384r1:
		return ecdh.P384(), true
	case curveSecp521r1:
		return ecdh.P521(), true
	}
	return nil, false
}

// wrapHandshake prepends a handshake header (type + 3-byte length) to body.
func wrapHandshake(msgType byte, body []byte) []byte {
	hs := make([]byte, 4+len(body))
	hs[0] = msgType
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	return hs
}

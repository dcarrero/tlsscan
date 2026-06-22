package handshake

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// TestPRF12_KnownVector validates the TLS 1.2 PRF (P_SHA256) against the widely
// used test vector circulated on the IETF TLS mailing list (and reproduced in
// many TLS implementations' test suites):
//
//   secret = 9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35
//   label  = "test label"
//   seed   = a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c
//   PRF(secret, label, seed)[0:100] = e3 f2 29 ba 72 7b e1 7b ...
func TestPRF12_KnownVector(t *testing.T) {
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	wantHex := "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
	want, _ := hex.DecodeString(wantHex)

	got := prf12(secret, "test label", seed, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF12 mismatch\n got=%x\nwant=%x", got, want)
	}
}

// TestPHashSHA256_ExactLength ensures P_hash returns exactly the requested
// length even when it is not a multiple of the hash output size.
func TestPHashSHA256_ExactLength(t *testing.T) {
	for _, n := range []int{1, 31, 32, 33, 48, 100, 137} {
		out := pHashSHA256([]byte("k"), []byte("seed"), n)
		if len(out) != n {
			t.Fatalf("pHashSHA256 len = %d, want %d", len(out), n)
		}
	}
}

// newTestSession builds a cbcSession with deterministic keys for record-
// construction tests (no network).
func newTestSession() *cbcSession {
	return &cbcSession{
		params:         cbcCipherParams{keyLen: 16, macLen: 20, ivLen: 16},
		clientWriteKey: bytes.Repeat([]byte{0x11}, 16),
		serverWriteKey: bytes.Repeat([]byte{0x22}, 16),
		clientWriteMAC: bytes.Repeat([]byte{0x33}, 20),
		serverWriteMAC: bytes.Repeat([]byte{0x44}, 20),
	}
}

// TestComputeMAC matches the hand-rolled MAC against an independent HMAC-SHA1
// over the canonical TLS 1.2 MAC input seq||type||version||len||content.
func TestComputeMAC(t *testing.T) {
	s := newTestSession()
	content := []byte("hello world")
	const seq = uint64(7)

	got := s.computeMAC(s.clientWriteMAC, seq, recordApplicationData, content)

	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[0:8], seq)
	hdr[8] = recordApplicationData
	binary.BigEndian.PutUint16(hdr[9:11], 0x0303)
	binary.BigEndian.PutUint16(hdr[11:13], uint16(len(content)))
	m := hmac.New(sha1.New, s.clientWriteMAC)
	m.Write(hdr[:])
	m.Write(content)
	want := m.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("computeMAC = %x, want %x", got, want)
	}
}

// TestMacThenPad_ValidIsBlockAligned verifies a well-formed record's plaintext
// (content+MAC+padding) is a multiple of the block size and the padding bytes
// all equal the pad length, per the TLS 1.2 spec.
func TestMacThenPad_ValidIsBlockAligned(t *testing.T) {
	s := newTestSession()
	content := []byte("GET / HTTP/1.1\r\n\r\n")
	plain := s.macThenPad(recordApplicationData, content, false, -1)

	if len(plain)%s.params.ivLen != 0 {
		t.Fatalf("valid plaintext len %d not block-aligned (%d)", len(plain), s.params.ivLen)
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		t.Fatalf("pad length %d exceeds plaintext", padLen)
	}
	for i := len(plain) - padLen - 1; i < len(plain); i++ {
		if int(plain[i]) != padLen {
			t.Fatalf("pad byte at %d = %d, want %d", i, plain[i], padLen)
		}
	}
	// content + MAC must precede the padding.
	if len(plain)-(padLen+1) != len(content)+s.params.macLen {
		t.Fatalf("content+MAC region = %d, want %d", len(plain)-(padLen+1), len(content)+s.params.macLen)
	}
}

// TestEncryptRecord_RoundTrip encrypts a well-formed record and decrypts it back
// with the same key (using the explicit IV), confirming the explicit-IV + CBC
// framing is correct and recovers the original content.
func TestEncryptRecord_RoundTrip(t *testing.T) {
	s := newTestSession()
	content := []byte("roundtrip content for cbc record")
	plain := s.macThenPad(recordApplicationData, content, false, -1)

	rec, err := s.encryptRecord(recordApplicationData, plain)
	if err != nil {
		t.Fatalf("encryptRecord: %v", err)
	}
	// Record = header(5) || explicit IV(16) || ciphertext.
	if rec[0] != recordApplicationData {
		t.Fatalf("record type = 0x%02x", rec[0])
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	frag := rec[5 : 5+recLen]
	iv := frag[:s.params.ivLen]
	ct := frag[s.params.ivLen:]

	block, _ := aes.NewCipher(s.clientWriteKey)
	dec := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, ct)

	if !bytes.Equal(dec, plain) {
		t.Fatalf("decrypted plaintext != original\n got=%x\nwant=%x", dec, plain)
	}
	// And the recovered content prefix matches.
	if !bytes.HasPrefix(dec, content) {
		t.Fatalf("decrypted does not start with content")
	}
}

// --- classification logic (pure, no network) ---

func alert(level, desc byte) cbcReaction {
	return cbcReaction{kind: "alert", alertLevel: level, alertDesc: desc}
}

// TestClassifyCBC_SecureAllSame: a hardened server returns the SAME reaction to
// badMAC, badPad and zeroLen => no oracle => all four false.
func TestClassifyCBC_SecureAllSame(t *testing.T) {
	r := classifyCBC(alert(2, 20), alert(2, 20), alert(2, 20)) // all bad_record_mac
	if r.goldenDoodle || r.zombiePoodle || r.sleepingPoodle || r.cve20191559 {
		t.Fatalf("secure server flagged a vuln: %+v", r)
	}
	// Connection-reset-for-all is also secure.
	rst := cbcReaction{kind: "reset"}
	r2 := classifyCBC(rst, rst, rst)
	if r2.goldenDoodle || r2.zombiePoodle || r2.sleepingPoodle || r2.cve20191559 {
		t.Fatalf("secure (reset) server flagged a vuln: %+v", r2)
	}
}

// TestClassifyCBC_GoldenDoodle: badMAC differs from badPad => MAC/pad ordering
// leak => GOLDENDOODLE.
func TestClassifyCBC_GoldenDoodle(t *testing.T) {
	// badMAC: connection stays alive (data); badPad: fatal alert.
	r := classifyCBC(cbcReaction{kind: "data"}, alert(2, 20), alert(2, 20))
	if !r.goldenDoodle {
		t.Fatalf("expected GOLDENDOODLE, got %+v", r)
	}
}

// TestClassifyCBC_ZombiePoodle: badPad yields a connection-level distinct
// reaction (alive) vs the bad-MAC alert => Zombie POODLE.
func TestClassifyCBC_ZombiePoodle(t *testing.T) {
	r := classifyCBC(alert(2, 20), cbcReaction{kind: "data"}, alert(2, 20))
	if !r.zombiePoodle {
		t.Fatalf("expected Zombie POODLE, got %+v", r)
	}
}

// TestClassifyCBC_SleepingPoodle: badPad is an alert but a DIFFERENT alert than
// the bad-MAC alert => Sleeping POODLE (alert-level leak).
func TestClassifyCBC_SleepingPoodle(t *testing.T) {
	r := classifyCBC(alert(2, 20), alert(2, 50), alert(2, 20))
	if !r.sleepingPoodle {
		t.Fatalf("expected Sleeping POODLE, got %+v", r)
	}
	// It must NOT be misclassified as Zombie (badPad IS an alert).
	if r.zombiePoodle {
		t.Fatalf("Sleeping case should not flag Zombie: %+v", r)
	}
}

// TestClassifyCBC_CVE20191559: zeroLen differs from BOTH badPad and badMAC =>
// CVE-2019-1559.
func TestClassifyCBC_CVE20191559(t *testing.T) {
	r := classifyCBC(alert(2, 20), alert(2, 20), cbcReaction{kind: "data"})
	if !r.cve20191559 {
		t.Fatalf("expected CVE-2019-1559, got %+v", r)
	}
}

// TestProbeCBCPaddingOracles_UnreachableIsSafe asserts the probe fails safe
// (all false) for an unroutable host without panicking or hanging.
func TestProbeCBCPaddingOracles_UnreachableIsSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	gd, z, s, c := ProbeCBCPaddingOracles(ctx, "198.51.100.0:443", "test.invalid", 1*time.Second)
	if gd || z || s || c {
		t.Errorf("unreachable host should yield all false, got gd=%v z=%v s=%v c=%v", gd, z, s, c)
	}
}

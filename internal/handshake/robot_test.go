package handshake

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestBuildPKCS1Vector_Correct validates the structure of a well-formed PKCS#1
// v1.5 block: 00 02 || PS(>=8 non-zero) || 00 || PMS(48), total length k.
func TestBuildPKCS1Vector_Correct(t *testing.T) {
	const k = 256 // 2048-bit RSA modulus
	pms := newPMS()
	if len(pms) != 48 {
		t.Fatalf("PMS length = %d, want 48", len(pms))
	}
	if pms[0] != 0x03 || pms[1] != 0x03 {
		t.Fatalf("PMS version prefix = %02x %02x, want 03 03", pms[0], pms[1])
	}

	block := buildPKCS1Vector(vecCorrect, k, pms)
	if len(block) != k {
		t.Fatalf("block length = %d, want %d", len(block), k)
	}
	if block[0] != 0x00 || block[1] != 0x02 {
		t.Fatalf("leading bytes = %02x %02x, want 00 02", block[0], block[1])
	}

	// Find the 0x00 delimiter and verify all padding bytes before it are non-zero
	// and there are at least 8 of them.
	delim := -1
	for i := 2; i < len(block); i++ {
		if block[i] == 0x00 {
			delim = i
			break
		}
	}
	if delim < 0 {
		t.Fatal("no 0x00 delimiter found in correct vector")
	}
	if psLen := delim - 2; psLen < 8 {
		t.Fatalf("padding string length = %d, want >= 8", psLen)
	}
	for i := 2; i < delim; i++ {
		if block[i] == 0x00 {
			t.Fatalf("padding byte at %d is zero, want non-zero", i)
		}
	}
	// The recovered message must equal the PMS and sit at the end.
	if got := block[delim+1:]; !bytes.Equal(got, pms) {
		t.Fatalf("recovered message != PMS")
	}
}

// TestBuildPKCS1Vector_WrongFirstBytes verifies the malformed leading bytes.
func TestBuildPKCS1Vector_WrongFirstBytes(t *testing.T) {
	const k = 256
	block := buildPKCS1Vector(vecWrongFirstBytes, k, newPMS())
	if len(block) != k {
		t.Fatalf("block length = %d, want %d", len(block), k)
	}
	if block[0] == 0x00 && block[1] == 0x02 {
		t.Fatalf("leading bytes = 00 02, want invalid (got %02x %02x)", block[0], block[1])
	}
	if block[0] != 0x41 || block[1] != 0x17 {
		t.Fatalf("leading bytes = %02x %02x, want 41 17", block[0], block[1])
	}
}

// TestBuildPKCS1Vector_No0x00 verifies there is no 0x00 delimiter anywhere after
// the 00 02 header.
func TestBuildPKCS1Vector_No0x00(t *testing.T) {
	const k = 256
	block := buildPKCS1Vector(vecNo0x00, k, newPMS())
	if len(block) != k {
		t.Fatalf("block length = %d, want %d", len(block), k)
	}
	if block[0] != 0x00 || block[1] != 0x02 {
		t.Fatalf("leading bytes = %02x %02x, want 00 02", block[0], block[1])
	}
	for i := 2; i < len(block); i++ {
		if block[i] == 0x00 {
			t.Fatalf("found unexpected 0x00 at index %d; vector must have no delimiter", i)
		}
	}
}

// TestBuildPKCS1Vector_0x00InPadding verifies a 0x00 sits inside the first 8
// padding bytes (an illegal position).
func TestBuildPKCS1Vector_0x00InPadding(t *testing.T) {
	const k = 256
	block := buildPKCS1Vector(vec0x00InPadding, k, newPMS())
	if block[0] != 0x00 || block[1] != 0x02 {
		t.Fatalf("leading bytes = %02x %02x, want 00 02", block[0], block[1])
	}
	// The first 0x00 after the header must fall within the mandatory 8-byte
	// non-zero padding window (indices 2..9).
	delim := -1
	for i := 2; i < len(block); i++ {
		if block[i] == 0x00 {
			delim = i
			break
		}
	}
	if delim < 2 || delim > 9 {
		t.Fatalf("0x00 position = %d, want within first 8 padding bytes (2..9)", delim)
	}
}

// TestBuildPKCS1Vector_0x00AtWrongPMSPos verifies well-formed framing but a wrong
// embedded TLS client_version in the recovered message.
func TestBuildPKCS1Vector_0x00AtWrongPMSPos(t *testing.T) {
	const k = 256
	block := buildPKCS1Vector(vec0x00AtWrongPMSPos, k, newPMS())
	if block[0] != 0x00 || block[1] != 0x02 {
		t.Fatalf("leading bytes = %02x %02x, want 00 02", block[0], block[1])
	}
	delim := -1
	for i := 2; i < len(block); i++ {
		if block[i] == 0x00 {
			delim = i
			break
		}
	}
	if delim < 0 || delim+2 >= len(block) {
		t.Fatal("no usable delimiter / message in wrong-PMS vector")
	}
	// Recovered message must NOT start with the correct TLS version 03 03.
	msg := block[delim+1:]
	if msg[0] == 0x03 && msg[1] == 0x03 {
		t.Fatalf("recovered version = 03 03, want a wrong client_version")
	}
}

// TestAllRobotVectors_LengthAndUniqueness ensures every vector has length k and
// that the five vectors are not all identical (each is a distinct test case).
func TestAllRobotVectors_LengthAndUniqueness(t *testing.T) {
	const k = 128 // 1024-bit modulus, smallest realistic case
	pms := newPMS()
	seen := make(map[string]bool)
	for _, kind := range allRobotVectors {
		b := buildPKCS1Vector(kind, k, pms)
		if len(b) != k {
			t.Fatalf("vector %d length = %d, want %d", kind, len(b), k)
		}
		seen[string(b)] = true
	}
	if len(seen) != len(allRobotVectors) {
		t.Fatalf("expected %d distinct vectors, got %d", len(allRobotVectors), len(seen))
	}
}

// TestSNIExtension checks the server_name extension framing.
func TestSNIExtension(t *testing.T) {
	if sniExtension("") != nil {
		t.Error("empty host should produce no SNI extension")
	}
	ext := sniExtension("example.com")
	if ext[0] != 0x00 || ext[1] != 0x00 {
		t.Fatalf("extension type = %02x %02x, want 00 00 (server_name)", ext[0], ext[1])
	}
	// type(2)+len(2)+listlen(2)+nametype(1)+namelen(2)+name(11) = 20
	if len(ext) != 4+2+1+2+len("example.com") {
		t.Fatalf("SNI extension length = %d, unexpected", len(ext))
	}
}

// TestProbeROBOT_UnreachableIsSafe asserts ProbeROBOT fails safe (false) for an
// unroutable host, without panicking or hanging.
func TestProbeROBOT_UnreachableIsSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if ProbeROBOT(ctx, "198.51.100.0:443", "test.invalid", 1*time.Second) {
		t.Error("ProbeROBOT should be false for an unreachable host")
	}
}

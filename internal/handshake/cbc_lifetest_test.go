package handshake

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"testing"
	"time"
)

// decryptServerRecord decrypts one server application-data/handshake fragment
// (explicit IV || ciphertext) and returns the plaintext CONTENT (MAC+padding
// stripped best-effort). Used ONLY by the life test to prove the session keys
// are correct by recovering real HTTP bytes from the server.
func (s *cbcSession) decryptServerRecord(frag []byte) ([]byte, bool) {
	if len(frag) < s.params.ivLen+s.params.ivLen {
		return nil, false
	}
	iv := frag[:s.params.ivLen]
	ct := frag[s.params.ivLen:]
	if len(ct)%s.params.ivLen != 0 {
		return nil, false
	}
	block, err := aes.NewCipher(s.serverWriteKey)
	if err != nil {
		return nil, false
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	// Strip TLS padding.
	if len(pt) == 0 {
		return nil, false
	}
	padLen := int(pt[len(pt)-1])
	if padLen+1 > len(pt) {
		return nil, false
	}
	pt = pt[:len(pt)-padLen-1]
	// Strip the MAC.
	if len(pt) < s.params.macLen {
		return nil, false
	}
	content := pt[:len(pt)-s.params.macLen]
	return content, true
}

// TestCBC_LifeProof is the mandatory proof-of-life for the hand-rolled CBC
// client. It is NOT a regular network assertion: it only runs when
// TLSSCAN_CBC_LIFETEST is set, and prints a detailed report. It iterates a list
// of candidate hosts (override with TLSSCAN_CBC_HOSTS) and, for the first that
// negotiates one of our CBC suites, completes the handshake, sends an HTTP GET
// over a well-formed application-data record, and decrypts the response to prove
// the keys are correct.
func TestCBC_LifeProof(t *testing.T) {
	if os.Getenv("TLSSCAN_CBC_LIFETEST") == "" {
		t.Skip("set TLSSCAN_CBC_LIFETEST=1 to run the CBC client proof-of-life")
	}
	hosts := []string{
		"www.google.com", "google.com", "www.microsoft.com", "support.apple.com",
		"www.yahoo.com", "www.bing.com", "www.amazon.com", "github.com",
		"www.cloudflare.com", "tls-v1-2.badssl.com:1012", "rc4-md5.badssl.com",
		"cbc.badssl.com", "mozilla-old.badssl.com",
	}
	if h := os.Getenv("TLSSCAN_CBC_HOSTS"); h != "" {
		hosts = []string{h}
	}

	for _, host := range hosts {
		addr := host
		sni := host
		if i := indexOfByte(host, ':'); i >= 0 {
			sni = host[:i]
		} else {
			addr = host + ":443"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		sess := establishCBCSession(ctx, addr, sni, 8*time.Second)
		if sess == nil {
			cancel()
			t.Logf("%-30s: no CBC session (suite not offered or handshake failed)", host)
			continue
		}
		t.Logf("%-30s: CBC HANDSHAKE ACCEPTED (server Finished received), suite keyLen=%d", host, sess.params.keyLen)

		// Send a well-formed HTTP request in a single application-data record.
		req := []byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\nUser-Agent: tlsscan-cbc-lifetest\r\n\r\n")
		if err := sess.sendCrafted(req, false, -1); err != nil {
			t.Logf("%-30s: send failed: %v", host, err)
			sess.conn.Close()
			cancel()
			continue
		}

		// Read and decrypt the first server data record.
		_ = sess.conn.SetReadDeadline(time.Now().Add(6 * time.Second))
		ct, _, recLen, err := readRecordHeader(sess.conn)
		if err != nil {
			t.Logf("%-30s: no response after GET: %v", host, err)
			sess.conn.Close()
			cancel()
			continue
		}
		if ct != recordApplicationData {
			t.Logf("%-30s: response record type=0x%02x (not app-data) len=%d", host, ct, recLen)
			sess.conn.Close()
			cancel()
			continue
		}
		frag := make([]byte, recLen)
		if _, err := readFull(sess.conn, frag); err != nil {
			t.Logf("%-30s: short read of response: %v", host, err)
			sess.conn.Close()
			cancel()
			continue
		}
		sess.serverSeq++
		plain, ok := sess.decryptServerRecord(frag)
		if !ok {
			t.Logf("%-30s: could not decrypt response fragment (len=%d)", host, len(frag))
			sess.conn.Close()
			cancel()
			continue
		}
		preview := plain
		if len(preview) > 48 {
			preview = preview[:48]
		}
		t.Logf("%-30s: DECRYPTED RESPONSE (%d bytes): %q", host, len(plain), string(preview))
		if len(plain) >= 4 && string(plain[:4]) == "HTTP" {
			t.Logf("%-30s: *** PROOF OF LIFE PASSED: decrypted real HTTP response ***", host)
		}
		sess.conn.Close()
		cancel()
	}
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

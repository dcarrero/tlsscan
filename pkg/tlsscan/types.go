// Package tlsscan provides a dependency-free TLS configuration scanner.
//
// It connects to a target host and probes its TLS configuration the same way
// a browser would: opening a TCP connection and performing TLS handshakes,
// one per protocol version and cipher, to map what the server accepts or
// rejects. It does NOT reimplement cryptography; it relies on Go's standard
// crypto/tls and crypto/x509, plus hand-crafted ClientHello bytes only for
// legacy protocols Go no longer supports natively (SSLv2/v3).
//
// The grading follows the SSL Labs Server Rating Guide (a public
// specification), not anyone else's code.
//
// License: MIT.
package tlsscan

import "time"

// Grade is the overall TLS letter grade, A+ down to F, plus T (trust issue)
// and R (could not evaluate / redirect).
type Grade string

const (
	GradeAPlus Grade = "A+"
	GradeA     Grade = "A"
	GradeB     Grade = "B"
	GradeC     Grade = "C"
	GradeD     Grade = "D"
	GradeE     Grade = "E"
	GradeF     Grade = "F"
	GradeT     Grade = "T" // trust problem (expired/self-signed/distrusted)
	GradeR     Grade = "R" // not rated
)

// Result is the complete output of a scan. This struct is the stable contract
// consumed by the Laravel gateway; field names map 1:1 to the JSON in the
// internal API spec (PHASE_0).
type Result struct {
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	Grade           Grade           `json:"grade"`
	GradeCaps       []string        `json:"grade_caps"`
	Protocols       Protocols       `json:"protocols"`
	Certificate     Certificate     `json:"certificate"`
	Ciphers         CipherSummary   `json:"ciphers"`
	ForwardSecrecy  bool            `json:"forward_secrecy"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
	Rating          RatingBreakdown `json:"rating"`
	ScanDurationMs  int64           `json:"scan_duration_ms"`
	RulesetVersion  string          `json:"ruleset_version"`
	Errors          []string        `json:"errors,omitempty"`
}

// Protocols records which TLS/SSL versions the server accepts.
type Protocols struct {
	SSL2   bool `json:"ssl2"`
	SSL3   bool `json:"ssl3"`
	TLS10  bool `json:"tls1_0"`
	TLS11  bool `json:"tls1_1"`
	TLS12  bool `json:"tls1_2"`
	TLS13  bool `json:"tls1_3"`
	ALPN   []string `json:"alpn,omitempty"`
	HTTP2  bool `json:"http2"`
}

// Certificate holds the leaf certificate analysis.
type Certificate struct {
	Valid          bool      `json:"valid"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	DaysToExpiry   int       `json:"days_to_expiry"`
	KeyType        string    `json:"key_type"` // RSA, ECDSA, Ed25519
	KeyBits        int       `json:"key_bits"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	ChainComplete  bool      `json:"chain_complete"`
	HostnameMatch  bool      `json:"hostname_match"`
	SelfSigned     bool      `json:"self_signed"`
	Distrusted     bool      `json:"distrusted"` // legacy Symantec etc.
	SANs           []string  `json:"sans,omitempty"`
}

// CipherSummary classifies the cipher suites the server supports.
type CipherSummary struct {
	Strong   []string `json:"strong"`
	Weak     []string `json:"weak"`
	Insecure []string `json:"insecure"`
	ServerPreferred bool `json:"server_preferred_order"`
}

// Vulnerabilities is the set of known TLS flaws checked. Each is true when the
// server is vulnerable. Includes flaws testssl.sh documents as not yet covered
// (GoldenDoodle, ZombiePoodle, SleepingPoodle, CVE-2019-1559, insecure
// renegotiation) so we can exceed its coverage.
type Vulnerabilities struct {
	Heartbleed            bool `json:"heartbleed"`
	Poodle                bool `json:"poodle"`
	Robot                 bool `json:"robot"`
	Sweet32               bool `json:"sweet32"`
	Drown                 bool `json:"drown"`
	Freak                 bool `json:"freak"`
	Logjam                bool `json:"logjam"`
	Beast                 bool `json:"beast"`
	GoldenDoodle          bool `json:"goldendoodle"`
	ZombiePoodle          bool `json:"zombie_poodle"`
	SleepingPoodle        bool `json:"sleeping_poodle"`
	ZeroLengthPaddingCVE  bool `json:"cve_2019_1559"`
	InsecureRenegotiation bool `json:"insecure_renegotiation"`
	TLSFallbackSCSV       bool `json:"tls_fallback_scsv_missing"`
}

// RatingBreakdown shows the SSL Labs Rating Guide component scores so the grade
// is transparent (a differentiator vs the black box of the original).
type RatingBreakdown struct {
	ProtocolScore    int `json:"protocol_score"`     // 0-100, weight 30%
	KeyExchangeScore int `json:"key_exchange_score"` // 0-100, weight 30%
	CipherScore      int `json:"cipher_score"`       // 0-100, weight 40%
	Numeric          int `json:"numeric"`            // weighted 0-100
}

// Options configure a scan.
type Options struct {
	Host       string
	Port       int           // default 443
	Timeout    time.Duration // default 15s
	CheckVulns bool          // run vulnerability probes (slower)
	IPVersion  string        // "", "4", "6"
}

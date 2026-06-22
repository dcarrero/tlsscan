package tlsscan

// rate implements the SSL Labs Server Rating Guide (a public specification).
// Returns the component breakdown, the final letter grade, and any grade caps
// that were applied. This is a transparent, documented re-implementation of the
// *spec* — not of testssl.sh or anyone else's code.
//
// Components (per the guide):
//   Protocol support   weight 30%
//   Key exchange       weight 30%
//   Cipher strength    weight 40%
// Then grade caps are applied (cert problems -> T, critical vulns -> F, etc.).
func rate(r *Result) (RatingBreakdown, Grade, []string) {
	caps := []string{}

	proto := protocolScore(r.Protocols)
	kx := keyExchangeScore(r.Certificate, r.ForwardSecrecy)
	cipher := cipherScore(r.Ciphers)

	numeric := (proto*30 + kx*30 + cipher*40) / 100
	b := RatingBreakdown{
		ProtocolScore:    proto,
		KeyExchangeScore: kx,
		CipherScore:      cipher,
		Numeric:          numeric,
	}

	grade := numericToGrade(numeric)

	// --- Grade caps ---

	// Trust problems cap to T.
	if !r.Certificate.Valid || r.Certificate.SelfSigned || r.Certificate.Distrusted || !r.Certificate.HostnameMatch {
		caps = append(caps, "certificate-trust")
		grade = GradeT
	}

	// Critical vulnerabilities cap to F.
	v := r.Vulnerabilities
	if v.Heartbleed || v.Robot || v.Drown || v.InsecureRenegotiation {
		caps = append(caps, "critical-vulnerability")
		grade = GradeF
	}

	// SSLv3 caps to C; SSLv2 caps to F.
	if r.Protocols.SSL2 {
		caps = append(caps, "ssl2-enabled")
		grade = GradeF
	} else if r.Protocols.SSL3 {
		caps = append(caps, "ssl3-enabled")
		grade = capAt(grade, GradeC)
	}

	// No forward secrecy caps to B.
	if !r.ForwardSecrecy {
		caps = append(caps, "no-forward-secrecy")
		grade = capAt(grade, GradeB)
	}

	// Any insecure cipher caps to C.
	if len(r.Ciphers.Insecure) > 0 {
		caps = append(caps, "insecure-cipher")
		grade = capAt(grade, GradeC)
	}

	// TLS 1.3 + clean config earns A+.
	if grade == GradeA && r.Protocols.TLS13 && len(r.Ciphers.Weak) == 0 &&
		len(r.Ciphers.Insecure) == 0 && r.Certificate.DaysToExpiry > 30 {
		grade = GradeAPlus
	}

	return b, grade, caps
}

func protocolScore(p Protocols) int {
	// Best protocol determines the ceiling; worst drags it down.
	switch {
	case p.SSL2 || p.SSL3:
		return 20
	case p.TLS10 || p.TLS11:
		return 70
	case p.TLS13:
		return 100
	case p.TLS12:
		return 90
	default:
		return 0
	}
}

func keyExchangeScore(c Certificate, fs bool) int {
	score := 0
	switch c.KeyType {
	case "RSA":
		switch {
		case c.KeyBits >= 4096:
			score = 100
		case c.KeyBits >= 2048:
			score = 90
		case c.KeyBits >= 1024:
			score = 40
		default:
			score = 20
		}
	case "ECDSA":
		if c.KeyBits >= 256 {
			score = 100
		} else {
			score = 60
		}
	}
	if !fs {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	return score
}

func cipherScore(c CipherSummary) int {
	if len(c.Insecure) > 0 {
		return 20
	}
	if len(c.Weak) > 0 && len(c.Strong) == 0 {
		return 50
	}
	if len(c.Weak) > 0 {
		return 80
	}
	if len(c.Strong) > 0 {
		return 100
	}
	return 0
}

func numericToGrade(n int) Grade {
	switch {
	case n >= 95:
		return GradeA // A+ decided later with extra conditions
	case n >= 80:
		return GradeA
	case n >= 65:
		return GradeB
	case n >= 50:
		return GradeC
	case n >= 35:
		return GradeD
	case n >= 20:
		return GradeE
	default:
		return GradeF
	}
}

// capAt returns the lower (worse) of current and ceiling.
func capAt(current, ceiling Grade) Grade {
	if gradeRank(current) > gradeRank(ceiling) {
		return ceiling
	}
	return current
}

// gradeRank: lower is better. A+ = 0 ... F = 7, T/R high.
func gradeRank(g Grade) int {
	order := map[Grade]int{
		GradeAPlus: 0, GradeA: 1, GradeB: 2, GradeC: 3,
		GradeD: 4, GradeE: 5, GradeF: 6, GradeT: 7, GradeR: 8,
	}
	return order[g]
}

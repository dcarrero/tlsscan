package handshake

// CBC padding-oracle detection (Craig Young's "Zombie POODLE / GOLDENDOODLE /
// Sleeping POODLE / 0-Length OpenSSL" family), built on top of the hand-rolled,
// proof-of-life-validated TLS 1.2 CBC client in cbc.go.
//
// TECHNIQUE (Young, DEF CON 2019 — "Practical Bleichenbacher / TLS 1.2 CBC
// padding oracles"). On an ESTABLISHED CBC session we send a crafted HTTP
// request inside a manipulated application-data record and observe the server's
// reaction. Four stimuli:
//
//   control : valid padding + valid MAC          -> a normal HTTP response.
//   badMAC  : valid padding + INVALID MAC        -> GOLDENDOODLE signal.
//   badPad  : INVALID padding (=> invalid MAC)   -> Zombie POODLE signal.
//   zeroLen : zero-length padding manipulation   -> CVE-2019-1559 / Sleeping.
//
// A correctly-implemented (constant-time, Lucky13-hardened) server treats badMAC,
// badPad and zeroLen IDENTICALLY: it returns bad_record_mac (encrypted alert) and
// tears the connection down the same way for all three. There is then NO oracle.
//
// A vulnerable server distinguishes these cases — different alert, or no alert at
// all (connection stays alive / different teardown). Young's mapping:
//   - GOLDENDOODLE   : the badMAC (valid-pad/invalid-MAC) case behaves DIFFERENTLY
//                      from the badPad case (the server leaks MAC-vs-pad order).
//   - Zombie POODLE  : the badPad case yields a DISTINCT, observable reaction vs
//                      the secure baseline (a "deterministic" different response).
//   - Sleeping POODLE: a variant of Zombie where the distinguishing signal is a
//                      different/encrypted alert rather than a connection-level one.
//   - CVE-2019-1559  : the zero-length-padding record produces a reaction distinct
//                      from the generic bad-padding one (the OpenSSL 0-byte-record
//                      MAC bypass leaks via a different alert path).
//
// CONSERVATIVE DECISION RULE (false positives are the worst outcome):
//   1. Establish a baseline "secure" reaction by sending the badMAC stimulus and
//      confirming it is reproducible. The secure expectation is that badMAC,
//      badPad and zeroLen all collapse to the SAME reaction.
//   2. For each manipulated vector, require its reaction to be REPRODUCIBLE
//      (repeated independently on fresh sessions) before it can mean anything.
//   3. Flag a specific vuln ONLY when its vector's reproducible reaction differs
//      from the others per the mapping above. If every manipulated vector yields
//      the same reaction => no oracle => all four false.
//   4. Any handshake failure / no-CBC-suite / transport noise / non-reproducible
//      result => all four false (fail safe).
//
// HONEST LIMITATION: we have no known-vulnerable reference server, so the
// true-positive path is validated by CONSTRUCTION (the differential logic + the
// proof-of-life CBC client), not against a live vulnerable target. The probe is
// deliberately tuned to never fire on modern servers (verified) at the cost of
// possibly missing a real, marginal oracle (an acceptable false negative).
//
// License: MIT.

import (
	"context"
	"time"
)

// cbcVector identifies one crafted application-data manipulation.
type cbcVector int

const (
	vecControl cbcVector = iota // valid pad + valid MAC
	vecBadMAC                   // valid pad + invalid MAC   -> GOLDENDOODLE
	vecBadPad                   // invalid pad               -> Zombie POODLE
	vecZeroLen                  // zero-length padding        -> CVE-2019-1559 / Sleeping
)

// cbcResult carries the four boolean verdicts.
type cbcResult struct {
	goldenDoodle   bool
	zombiePoodle   bool
	sleepingPoodle bool
	cve20191559    bool
}

// ProbeCBCPaddingOracles reports the four CBC padding-oracle verdicts (in order:
// GoldenDoodle, ZombiePoodle, SleepingPoodle, CVE-2019-1559). It is fully
// fail-safe: if the server negotiates no CBC suite, if the hand-rolled handshake
// cannot be established, or if results are not cleanly reproducible, every
// verdict is false. host is the SNI name; addr is "host:port".
func ProbeCBCPaddingOracles(ctx context.Context, addr, host string, timeout time.Duration) (gd, zombie, sleeping, cve bool) {
	// Cap the whole probe: each vector opens a fresh session (a full handshake),
	// we repeat for reproducibility, so bound per-session latency tightly and put
	// a hard ceiling on the entire probe so it can never approach the 15s budget.
	per := capTimeout(timeout)
	if per > 3*time.Second {
		per = 3 * time.Second
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	// Applicability gate: can we even establish a CBC session at all? If not, the
	// family is N/A => all false. We also use this to avoid wasting probes on
	// AEAD-only servers.
	probe := func() *cbcSession { return establishCBCSession(ctx, addr, host, per) }
	if s := probe(); s != nil {
		s.conn.Close()
	} else {
		return false, false, false, false
	}

	// Two repetitions are enough to reject non-deterministic noise while keeping
	// the probe fast (matches the ROBOT probe). The control vector is not needed
	// for the differential decision (we compare the three manipulated vectors
	// against each other), so we skip it to save handshakes and stay well under
	// the latency budget.
	const reps = 2

	badMAC, okM := stableCBCReaction(ctx, addr, host, vecBadMAC, reps, per)
	if !okM {
		return false, false, false, false
	}
	badPad, okP := stableCBCReaction(ctx, addr, host, vecBadPad, reps, per)
	if !okP {
		return false, false, false, false
	}
	zeroLen, okZ := stableCBCReaction(ctx, addr, host, vecZeroLen, reps, per)
	if !okZ {
		return false, false, false, false
	}

	res := classifyCBC(badMAC, badPad, zeroLen)
	return res.goldenDoodle, res.zombiePoodle, res.sleepingPoodle, res.cve20191559
}

// classifyCBC applies Young's conservative mapping to the three reproducible
// manipulated-vector reactions. The SECURE invariant is badMAC == badPad ==
// zeroLen (all collapse to the same bad_record_mac teardown). Any deviation from
// that invariant is a leak; we attribute it to the most specific vuln.
//
// This function is pure so the decision logic can be unit-tested with simulated
// reactions (no network).
func classifyCBC(badMAC, badPad, zeroLen cbcReaction) cbcResult {
	var r cbcResult

	macVsPadDiffer := !badMAC.equal(badPad)
	zeroVsPadDiffer := !zeroLen.equal(badPad)
	zeroVsMacDiffer := !zeroLen.equal(badMAC)

	// SECURE CASE: everything identical => no oracle. Return all false.
	if !macVsPadDiffer && !zeroVsPadDiffer {
		return r
	}

	// GOLDENDOODLE: the valid-pad/invalid-MAC vector is distinguishable from the
	// invalid-pad vector. This is the canonical MAC-vs-pad ordering leak: the
	// server reveals that it checked padding before the MAC (or vice versa) by
	// reacting differently to a MAC-only failure than to a padding failure.
	if macVsPadDiffer {
		r.goldenDoodle = true
	}

	// Zombie POODLE: the invalid-padding vector yields a CONNECTION-LEVEL distinct
	// reaction (the connection survives, or tears down differently) versus the
	// MAC-failure vector. We attribute Zombie when badPad differs from badMAC and
	// the badPad reaction is NOT a standard fatal alert (i.e. the server did not
	// simply send bad_record_mac and close — it leaked via liveness).
	if macVsPadDiffer && badPad.kind != "alert" && badPad.kind != badMAC.kind {
		r.zombiePoodle = true
	}

	// Sleeping POODLE: a Zombie variant where the distinguishing signal IS a
	// different alert (an alert-level leak) rather than a liveness leak. badPad
	// differs from badMAC and badPad is an alert with a different tag.
	if macVsPadDiffer && badPad.kind == "alert" && badMAC.kind == "alert" &&
		(badPad.alertLevel != badMAC.alertLevel || badPad.alertDesc != badMAC.alertDesc) {
		r.sleepingPoodle = true
	}

	// CVE-2019-1559 (0-length OpenSSL): the zero-length-padding vector is
	// distinguishable from BOTH the generic bad-padding and the bad-MAC vectors.
	// The OpenSSL 0-byte-record MAC bypass surfaces as its own reaction path.
	if zeroVsPadDiffer && zeroVsMacDiffer {
		r.cve20191559 = true
	}

	return r
}

// stableCBCReaction performs the crafted exchange for a vector `reps` times on
// fresh sessions and returns the reaction only if every repetition agrees. ok is
// false when repetitions disagree or any session could not be established.
func stableCBCReaction(ctx context.Context, addr, host string, vec cbcVector, reps int, timeout time.Duration) (cbcReaction, bool) {
	var first cbcReaction
	for i := 0; i < reps; i++ {
		react, ok := cbcExchange(ctx, addr, host, vec, timeout)
		if !ok {
			return cbcReaction{}, false
		}
		if i == 0 {
			first = react
			continue
		}
		if !react.equal(first) {
			return cbcReaction{}, false // non-deterministic => fail safe
		}
	}
	return first, true
}

// cbcExchange establishes a fresh CBC session, sends one crafted HTTP request
// record for the given vector, and returns the server's classified reaction. ok
// is false if the session could not be established (transport/applicability).
func cbcExchange(ctx context.Context, addr, host string, vec cbcVector, timeout time.Duration) (cbcReaction, bool) {
	sess := establishCBCSession(ctx, addr, host, timeout)
	if sess == nil {
		return cbcReaction{}, false
	}
	defer sess.conn.Close()

	// A well-formed HTTP request as the cleartext content; the manipulation is in
	// the MAC/padding of the record, not the content.
	req := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")

	var forceBadMAC bool
	var padOverride int = -1
	switch vec {
	case vecControl:
		forceBadMAC, padOverride = false, -1
	case vecBadMAC:
		forceBadMAC, padOverride = true, -1 // valid padding, invalid MAC
	case vecBadPad:
		// Invalid padding: emit an explicit, self-inconsistent pad (value 255 but
		// only a few bytes), which is not a valid TLS pad. This also corrupts the
		// implied MAC boundary => invalid MAC by construction.
		forceBadMAC, padOverride = false, 255
	case vecZeroLen:
		// Zero-length padding manipulation: a single pad byte of value 0 means
		// "zero padding bytes follow", the degenerate case CVE-2019-1559 abuses.
		forceBadMAC, padOverride = true, 0
	}

	if err := sess.sendCrafted(req, forceBadMAC, padOverride); err != nil {
		return cbcReaction{}, false
	}

	// A short response window: a server that rejects the bad record answers
	// immediately (alert/close/reset); a hardened server that silently drops it
	// would otherwise stall, but "timeout" is itself a stable, comparable
	// reaction, so a short cap is safe and keeps the probe fast.
	respTimeout := timeout
	if respTimeout > 1200*time.Millisecond {
		respTimeout = 1200 * time.Millisecond
	}
	return sess.readReaction(respTimeout), true
}

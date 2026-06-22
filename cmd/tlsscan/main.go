// Command tlsscan is the console interface to the tlsscan library.
//
//	tlsscan example.com
//	tlsscan -json -vulns -port 443 example.com
//
// License: MIT.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dcarrero/tlsscan/pkg/tlsscan"
)

func main() {
	var (
		port    = flag.Int("port", 443, "target port")
		timeout = flag.Duration("timeout", 15*time.Second, "scan timeout")
		vulns   = flag.Bool("vulns", false, "run vulnerability probes (slower)")
		asJSON  = flag.Bool("json", false, "output JSON instead of text")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: tlsscan [flags] <host>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	host := flag.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+5*time.Second)
	defer cancel()

	res, err := tlsscan.Scan(ctx, tlsscan.Options{
		Host:       host,
		Port:       *port,
		Timeout:    *timeout,
		CheckVulns: *vulns,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}

	printText(res)
}

func printText(r *tlsscan.Result) {
	fmt.Printf("Host:   %s:%d\n", r.Host, r.Port)
	fmt.Printf("Grade:  %s", r.Grade)
	if len(r.GradeCaps) > 0 {
		fmt.Printf("  (caps: %v)", r.GradeCaps)
	}
	fmt.Println()
	fmt.Printf("Rating: %d/100  (proto %d, kx %d, cipher %d)\n",
		r.Rating.Numeric, r.Rating.ProtocolScore, r.Rating.KeyExchangeScore, r.Rating.CipherScore)
	fmt.Printf("Protocols: TLS1.3=%v TLS1.2=%v TLS1.1=%v TLS1.0=%v SSL3=%v SSL2=%v\n",
		r.Protocols.TLS13, r.Protocols.TLS12, r.Protocols.TLS11, r.Protocols.TLS10, r.Protocols.SSL3, r.Protocols.SSL2)
	fmt.Printf("Forward Secrecy: %v\n", r.ForwardSecrecy)
	fmt.Printf("Certificate: valid=%v expires in %d days, %s %d-bit, host-match=%v\n",
		r.Certificate.Valid, r.Certificate.DaysToExpiry, r.Certificate.KeyType, r.Certificate.KeyBits, r.Certificate.HostnameMatch)
	fmt.Printf("Ciphers: %d strong, %d weak, %d insecure\n",
		len(r.Ciphers.Strong), len(r.Ciphers.Weak), len(r.Ciphers.Insecure))
	v := r.Vulnerabilities
	fmt.Printf("Vulns: heartbleed=%v drown=%v freak=%v logjam=%v poodle=%v beast=%v sweet32=%v insecure_reneg=%v fallback_scsv_missing=%v\n",
		v.Heartbleed, v.Drown, v.Freak, v.Logjam, v.Poodle, v.Beast, v.Sweet32, v.InsecureRenegotiation, v.TLSFallbackSCSV)
	if len(r.Errors) > 0 {
		fmt.Printf("Errors: %v\n", r.Errors)
	}
	fmt.Printf("Scanned in %dms (ruleset %s)\n", r.ScanDurationMs, r.RulesetVersion)
}

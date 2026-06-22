// Command headerforge-tls is the HTTP microservice wrapping the tlsscan library.
// The Laravel gateway POSTs to /v1/scan over the private network and receives
// the JSON Result. Listens only on a private/loopback address by default.
//
// License: MIT.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dcarrero/tlsscan/pkg/tlsscan"
)

type scanRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	TimeoutMs  int    `json:"timeout_ms"`
	CheckVulns bool   `json:"check_vulns"`
}

func main() {
	addr := os.Getenv("TLS_SCAN_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8081" // private by default; reverse-proxied internally
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/scan", handleScan)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("headerforge-tls listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	timeout := 15 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout+5*time.Second)
	defer cancel()

	res, err := tlsscan.Scan(ctx, tlsscan.Options{
		Host:       req.Host,
		Port:       req.Port,
		Timeout:    timeout,
		CheckVulns: req.CheckVulns,
	})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

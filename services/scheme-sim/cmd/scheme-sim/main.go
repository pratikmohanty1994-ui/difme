// scheme-sim: the simulated card network (ISO 8583 over TCP on :8583) with its admin API (HTTP on :8080).
// Optional SEED_CARDS: a JSON list of test cards to load at start.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/ntadapter"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/scheme"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/server"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	n := scheme.New()
	if u := os.Getenv("HSM_URL"); u != "" {
		n.HSM = threeds.NewHSMClient(u)        // 3-D Secure CAVV verification (ADR-027)
		n.Tokens.HSM = threeds.NewHSMClient(u) // network token cryptograms as TAVV (ADR-024/026)
	}
	if u := os.Getenv("ISSUER_URL"); u != "" {
		n.Issuer = scheme.NewIssuerClient(u) // card-issuer is the issuer host for its cards (ADR-024)
	}
	if seed := os.Getenv("SEED_CARDS"); seed != "" {
		var cards []scheme.Card
		if err := json.Unmarshal([]byte(seed), &cards); err != nil {
			log.Fatalf("SEED_CARDS: %v", err)
		}
		for _, c := range cards {
			if err := n.PutCard(c); err != nil {
				log.Fatalf("SEED_CARDS %s: %v", scheme.Mask(c.PAN), err)
			}
		}
		log.Printf("seeded %d test cards", len(cards))
	}
	l, err := net.Listen("tcp", env("ISO_LISTEN", ":8583"))
	if err != nil {
		log.Fatal(err)
	}
	go func() { log.Fatal(server.ServeISO(l, n)) }()
	var handler http.Handler = server.Admin(n)
	// Network tokenization service for Hyperswitch (ADR-024): /nts/* when configured. The JWE private key stays in
	// the security module (key nts-jwe); Hyperswitch's public key (PEM) encrypts the responses.
	if key, pubPEM, hsm := os.Getenv("NTS_API_KEY"), os.Getenv("NTS_HYPERSWITCH_PUBLIC_KEY"), os.Getenv("HSM_URL"); key != "" && pubPEM != "" && hsm != "" {
		blk, _ := pem.Decode([]byte(pubPEM))
		if blk == nil {
			log.Fatal("NTS_HYPERSWITCH_PUBLIC_KEY: PEM public key required")
		}
		pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
		rsaPub, ok := pk.(*rsa.PublicKey)
		if err != nil || !ok {
			log.Fatal("NTS_HYPERSWITCH_PUBLIC_KEY: RSA public key required")
		}
		nts := ntadapter.New(n.Tokens, env("NTS_REQUESTOR", "HYPERSWITCH"), key, env("NTS_KEY_ID", "nts-jwe"), ntadapter.HSMUnwrap(hsm, "nts-jwe"), rsaPub)
		nts.PublicKey = ntadapter.HSMPublicKey(hsm, "nts-jwe")
		mux := http.NewServeMux()
		mux.Handle("/nts/", nts.Handler("/nts"))
		mux.Handle("/", handler)
		handler = mux
		log.Printf("network tokenization service for Hyperswitch on /nts")
	}
	srv := &http.Server{Addr: env("HTTP_LISTEN", ":8080"), Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("scheme-sim: ISO 8583 on %s, admin on %s", l.Addr(), srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

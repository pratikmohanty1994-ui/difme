// scheme-sim: the simulated card network (ISO 8583 over TCP on :8583) with its admin API (HTTP on :8080).
// Optional SEED_CARDS: a JSON list of test cards to load at start.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

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
		n.HSM = threeds.NewHSMClient(u) // 3-D Secure CAVV verification (ADR-027)
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
	srv := &http.Server{Addr: env("HTTP_LISTEN", ":8080"), Handler: server.Admin(n), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("scheme-sim: ISO 8583 on %s, admin on %s", l.Addr(), srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

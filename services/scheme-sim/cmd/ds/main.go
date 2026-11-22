// Command ds runs DIFME's EMV 3DS directory server simulator (internal/ds, ADR-027).
//
//	DS_ADDR              listen address (default :8091)
//	DS_CARD_RANGES       card-range table as JSON: [{"prefix":"437551","acsURL":"http://acs:8090/3ds/areq"}]
//	DS_CARD_RANGES_FILE  the same table from a file (used when DS_CARD_RANGES is empty)
//	DS_URL               dsURL sent to ACSs in the AReq: where they post RReqs (e.g. http://ds:8091/3ds/rreq)
//	DS_REFERENCE_NUMBER  dsReferenceNumber (default DIFME-DS-SIM)
//	HSM_URL              security module (services/hsm): attempts CAVVs when the DS stands in
//
// Card ranges without an entry, and ACSs that cannot be reached, get the stand-in answer: transStatus A with an
// attempts CAVV (ECI 06).
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/ds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	raw := []byte(os.Getenv("DS_CARD_RANGES"))
	if len(raw) == 0 {
		if p := os.Getenv("DS_CARD_RANGES_FILE"); p != "" {
			var err error
			if raw, err = os.ReadFile(p); err != nil {
				log.Fatalf("DS_CARD_RANGES_FILE: %v", err)
			}
		}
	}
	var ranges []ds.Range
	if len(raw) > 0 {
		var err error
		if ranges, err = ds.ParseRanges(raw); err != nil {
			log.Fatal(err)
		}
	}
	d := ds.New(ds.Config{Ranges: ranges, HSM: threeds.NewHSMClient(env("HSM_URL", "http://127.0.0.1:8700")),
		Reference: os.Getenv("DS_REFERENCE_NUMBER"), URL: os.Getenv("DS_URL")})
	addr := env("DS_ADDR", ":8091")
	log.Printf("ds listening on %s, %d card range(s)", addr, len(ranges))
	log.Fatal((&http.Server{Addr: addr, Handler: d.Handler(), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

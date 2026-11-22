// Command acs runs DIFME's lightweight 3-D Secure ACS (ADR-027).
//
//	ACS_ADDR            listen address (default :8090)
//	ACS_CMS_URL         card management (scheme-sim card API today)
//	HSM_URL             security module (services/hsm)
//	TAZAMA_TMS_URL, TAZAMA_ADMIN_URL, TAZAMA_BUDGET_MS   FRM; without them every authentication is challenged
//	ACS_DS_URL          directory server results endpoint for RReqs (empty: not sent)
//	ACS_CHALLENGE_URL   acsURL given in ARes for challenges
//	ACS_FRICTIONLESS_LIMIT_MINOR   frictionless ceiling (default 500000 = INR 5,000)
//	ACS_PAYER_KEY       HMAC key for card references sent to FRM and for passcode hashing (required)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

type noFRM struct{}

func (noFRM) Evaluate(context.Context, string, string, string, int64, string) (acs.Verdict, string) {
	return acs.Unknown, "FRM not configured"
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	key := os.Getenv("ACS_PAYER_KEY")
	if len(key) < 16 {
		log.Fatal("ACS_PAYER_KEY (at least 16 characters) is required")
	}
	limit, _ := strconv.ParseInt(env("ACS_FRICTIONLESS_LIMIT_MINOR", "500000"), 10, 64)
	var frm acs.FRM = noFRM{}
	if tms, admin := os.Getenv("TAZAMA_TMS_URL"), os.Getenv("TAZAMA_ADMIN_URL"); tms != "" && admin != "" {
		ms, _ := strconv.Atoi(env("TAZAMA_BUDGET_MS", "3000"))
		frm = acs.NewTazama(tms, admin, time.Duration(ms)*time.Millisecond)
	}
	signer, err := acs.DevSigner() // TODO(ADR-027): scheme-issued ACS certificate chain from OpenBao
	if err != nil {
		log.Fatal(err)
	}
	a := acs.New(acs.Config{FrictionlessLimitMinor: limit, ChallengeURL: env("ACS_CHALLENGE_URL", "http://acs/3ds/creq"), PayerKey: []byte(key), Signer: signer},
		acs.NewCMSClient(env("ACS_CMS_URL", "http://127.0.0.1:8080")), frm, threeds.NewHSMClient(env("HSM_URL", "http://127.0.0.1:8700")),
		acs.LogOTP{}, acs.LogOOB{}, acs.NewDSClient(os.Getenv("ACS_DS_URL")))
	go func() { // decoupled authentications past their maximum time get their RReq
		for range time.Tick(30 * time.Second) {
			a.Expire(context.Background())
		}
	}()
	addr := env("ACS_ADDR", ":8090")
	log.Printf("acs listening on %s", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

// Command acs runs DIFME's lightweight 3-D Secure ACS (ADR-027).
//
//	ACS_ADDR            listen address (default :8090)
//	ACS_CMS_URL         card management (scheme-sim card API today)
//	HSM_URL             security module (services/hsm)
//	TAZAMA_TMS_URL, TAZAMA_ADMIN_URL, TAZAMA_BUDGET_MS   FRM; without them every authentication is challenged
//	ACS_DS_URL          directory server results endpoint for RReqs (empty: not sent)
//	ACS_CHALLENGE_URL   acsURL given in ARes for challenges
//	ACS_FRICTIONLESS_LIMIT_MINOR   frictionless ceiling (default 500000 = INR 5,000)
//	ACS_DATABASE_URL    PostgreSQL for pending challenges (table acs_challenge, created if missing); empty: in memory
//	                    (a restart loses them). App-channel session keys are never stored: an app-channel challenge
//	                    open when the process restarts ends with transStatus U (RReq sent at start-up).
//	ACS_INSTANCE        this instance's name for that recovery (default: host name, i.e. the pod name)
//	ACS_SIGNING_CERT_CHAIN  PEM file, leaf first: the scheme-issued ACS signing certificate chain presented in
//	                    acsSignedContent's x5c; the leaf's key is the security module's acs-sign key, which still signs.
//	                    Empty: the security module's own certificate.
//	ACS_FIDO_RP_ID      WebAuthn relying party id (the ACS/issuer domain); set to turn on WebAuthn / SPC authentication
//	                    and the issuer app's credential registration (/3ds/fido/...). Credentials live in
//	                    ACS_DATABASE_URL (table acs_fido_credential, sealed) or in memory.
//	ACS_FIDO_RP_NAME    relying party display name
//	ACS_FIDO_ORIGINS    comma-separated origins allowed in client data: the ACS challenge page origin, the issuer web
//	                    app, opaque app origins (android:apk-key-hash:...)
//	ACS_FIDO_TRUSTED_REQUESTOR_RP_IDS  comma-separated 3DS Requestor rpIds whose FIDO Authentication Data is trusted
//	ACS_ISSUER_TOKEN    optional bearer token required on the issuer endpoints (out-of-band answer, FIDO registration)
//	                    in addition to the mesh policy
package main

import (
	"context"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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

func list(k string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(k), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	limit, _ := strconv.ParseInt(env("ACS_FRICTIONLESS_LIMIT_MINOR", "500000"), 10, 64)
	var frm acs.FRM = noFRM{}
	if tms, admin := os.Getenv("TAZAMA_TMS_URL"), os.Getenv("TAZAMA_ADMIN_URL"); tms != "" && admin != "" {
		ms, _ := strconv.Atoi(env("TAZAMA_BUDGET_MS", "3000"))
		frm = acs.NewTazama(tms, admin, time.Duration(ms)*time.Millisecond)
	}
	// The ACS holds no keys: signing (acsSignedContent) and HMAC (card references, passcodes) happen in the security
	// module, whose keys come only through attested key release (ADR-026).
	hsmURL := env("HSM_URL", "http://127.0.0.1:8700")
	var chain []*x509.Certificate
	if p := os.Getenv("ACS_SIGNING_CERT_CHAIN"); p != "" {
		var err error
		if chain, err = acs.LoadCertChain(p); err != nil {
			log.Fatalf("ACS_SIGNING_CERT_CHAIN: %v", err)
		}
	}
	var signer *acs.Signer
	for i := 0; ; i++ {
		var err error
		if signer, err = acs.HSMSignerWithChain(hsmURL, chain); err == nil {
			break
		} else if i == 60 {
			log.Fatalf("security module signing certificate: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	host, _ := os.Hostname()
	cfg := acs.Config{FrictionlessLimitMinor: limit, ChallengeURL: env("ACS_CHALLENGE_URL", "http://acs/3ds/creq"), Signer: signer,
		MAC: acs.HSMMAC(hsmURL), Instance: env("ACS_INSTANCE", host),
		FIDO: acs.FIDOConfig{RPID: os.Getenv("ACS_FIDO_RP_ID"), RPName: os.Getenv("ACS_FIDO_RP_NAME"), Origins: list("ACS_FIDO_ORIGINS"),
			TrustedRequestorRPIDs: list("ACS_FIDO_TRUSTED_REQUESTOR_RP_IDS")}}
	if t := os.Getenv("ACS_ISSUER_TOKEN"); t != "" {
		cfg.IssuerAuth = acs.BearerAuth(t)
	}
	if url := os.Getenv("ACS_DATABASE_URL"); url != "" {
		store, err := acs.NewPostgresStore(context.Background(), url)
		if err != nil {
			log.Fatalf("ACS_DATABASE_URL: %v", err)
		}
		defer store.Close()
		sealed := store.Seal(acs.HSMSealer{URL: hsmURL}) // documents carry the card number: ciphertext only at rest
		cfg.Store, cfg.Credentials = sealed, sealed      // FIDO credentials: sealed the same way
	}
	a := acs.New(cfg,
		acs.NewCMSClient(env("ACS_CMS_URL", "http://127.0.0.1:8080")), frm, threeds.NewHSMClient(env("HSM_URL", "http://127.0.0.1:8700")),
		acs.LogOTP{}, acs.LogOOB{}, acs.NewDSClient(os.Getenv("ACS_DS_URL")))
	if n, err := a.Recover(context.Background()); err != nil {
		log.Fatalf("challenge store: %v", err)
	} else if n > 0 {
		log.Printf("ended %d app-channel challenge(s) whose session keys were lost with the previous process (transStatus U)", n)
	}
	go func() { // decoupled authentications past their maximum time get their RReq
		for range time.Tick(30 * time.Second) {
			a.Expire(context.Background())
		}
	}()
	addr := env("ACS_ADDR", ":8090")
	log.Printf("acs listening on %s", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

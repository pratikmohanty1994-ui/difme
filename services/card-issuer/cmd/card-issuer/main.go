// Command card-issuer runs DIFME's card issuer (ADR-024/025).
//
//	ADDR (":8080"), BIN ("437551"), HSM_URL, FINERACT_URL (…/fineract-provider), FINERACT_TENANT ("default"),
//	FINERACT_PAYMENT_TYPE (Fineract payment type id for card withdrawals),
//	FINERACT_TOKEN_URL + FINERACT_CLIENT_ID + FINERACT_CLIENT_SECRET (Keycloak, cluster) or FINERACT_USER + FINERACT_PASSWORD (local)
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/pratikmohanty1994/difme/services/card-issuer/internal/issuer"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	f := &issuer.Fineract{BaseURL: env("FINERACT_URL", "http://fineract.rails.svc:8080/fineract-provider"), Tenant: env("FINERACT_TENANT", "default"),
		TokenURL: os.Getenv("FINERACT_TOKEN_URL"), ClientID: os.Getenv("FINERACT_CLIENT_ID"), ClientSecret: os.Getenv("FINERACT_CLIENT_SECRET"),
		User: os.Getenv("FINERACT_USER"), Password: os.Getenv("FINERACT_PASSWORD"), HTTP: &http.Client{Timeout: 10 * time.Second}}
	if pt, err := strconv.ParseInt(os.Getenv("FINERACT_PAYMENT_TYPE"), 10, 64); err == nil {
		f.PaymentTypeID = pt
	}
	i := issuer.New(env("BIN", "437551"), f, issuer.NewHSMClient(env("HSM_URL", "http://hsm.rails.svc:8700")), issuer.NewMemStore())
	addr := env("ADDR", ":8080")
	log.Printf("card-issuer on %s", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: issuer.Handler(i), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

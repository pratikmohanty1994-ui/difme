// Command card-issuer runs DIFME's card issuer (ADR-024/025).
//
//	DATABASE_URL (Postgres; without it cards live in memory), ADDR (":8080"), BIN ("437551"), HSM_URL, FINERACT_URL (…/fineract-provider), FINERACT_TENANT ("default"),
//	FINERACT_PAYMENT_TYPE (Fineract payment type id for card withdrawals),
//	FINERACT_TOKEN_URL + FINERACT_CLIENT_ID + FINERACT_CLIENT_SECRET (Keycloak, cluster) or FINERACT_USER + FINERACT_PASSWORD (local)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
	_ "time/tzdata" // distroless image has no zoneinfo

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
	if loc, err := time.LoadLocation(env("FINERACT_TIMEZONE", "Asia/Kolkata")); err == nil {
		f.Location = loc // the tenant's timezone (deploy/platform/rails/fineract: Asia/Kolkata)
	} else {
		log.Fatalf("FINERACT_TIMEZONE: %v", err)
	}
	if pt, err := strconv.ParseInt(os.Getenv("FINERACT_PAYMENT_TYPE"), 10, 64); err == nil {
		f.PaymentTypeID = pt
	}
	h := issuer.NewHSMClient(env("HSM_URL", "http://hsm.rails.svc:8700"))
	var store issuer.Store = issuer.NewMemStore()
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" { // cluster: shared Postgres, PANs only sealed by the card vault
		var err error
		for i := 0; ; i++ {
			if store, err = issuer.NewPGStore(context.Background(), dsn, h); err == nil {
				break
			} else if i == 30 {
				log.Fatalf("database: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}
	i := issuer.New(env("BIN", "437551"), f, h, store)
	go func() { // daily billing: statements and interest-free grace (ADR-025)
		for ; ; time.Sleep(24 * time.Hour) {
			if m, g, err := i.RunBilling(context.Background()); err != nil {
				log.Printf("billing: %v", err)
			} else if m+g > 0 {
				log.Printf("billing: %d statements, %d grace settlements", m, g)
			}
		}
	}()
	addr := env("ADDR", ":8080")
	log.Printf("card-issuer on %s", addr)
	log.Fatal((&http.Server{Addr: addr, Handler: issuer.Handler(i), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

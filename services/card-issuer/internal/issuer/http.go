package issuer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Handler: the issuer's API.
//
//	POST /v1/cards                       issue (returns PAN and CVV2 once)
//	GET  /v1/cards/{id}                  card (masked)
//	POST /v1/cards/{id}/renew            {"reason":"RENEWAL|REPLACEMENT|LOST_STOLEN","graceDays":45}: new card / expiry, PAN and CVV2 once
//	PUT  /v1/cards/{id}/status           {"status":"BLOCKED"}
//	POST /v1/cards/{id}/pin              {"pinBlock":"<ISO 9564 format 4, hex>"} (app PIN set)
//	POST /v1/cards/{id}/pin/generate     random PIN (issuance / reset): {"appPinBlock": ISO 4 under the app key}
//	POST /v1/cards/{id}/pin/reveal       {"appPublicKey":"<SPKI, base64>"}: the generated PIN once, as a JWE to the app's key
//	GET  /v1/cards/{id}/dcvv2            the current dynamic CVV2 (app display)
//	GET  /v1/cards/{id}/open-to-buy
//	GET  /v1/cards/{pan}  (card management lookup for the ACS: expiry, status, channels; the path segment is a PAN)
//	POST /v1/cards/{id}/statements       close the billing cycle (credit): {"cycleDays":30}
//	POST /v1/cards/{id}/statements/latest/grace  at the due date: waive the interest when paid in full
//	POST /v1/authorisations              the switch's issuer authorisation
//	POST /v1/authorisations/{id}/clear   {"amountMinor":…, "icc":"<field 55 hex, card-present>"}
//	POST /v1/authorisations/{id}/reverse
func Handler(i *Issuer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /v1/cards", func(w http.ResponseWriter, r *http.Request) {
		var q IssueRequest
		if !decode(w, r, &q) {
			return
		}
		c, err := i.Issue(r.Context(), q)
		reply(w, 201, c, err)
	})
	mux.HandleFunc("GET /v1/cards/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var c Card
		var err error
		if len(id) >= 12 && isDigits(id) { // the ACS looks cards up by PAN
			c, err = i.CardByPAN(r.Context(), id)
		} else {
			c, err = i.Card(r.Context(), id)
		}
		reply(w, 200, c, err)
	})
	mux.HandleFunc("POST /v1/cards/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
		var q RenewRequest
		if !decode(w, r, &q) {
			return
		}
		c, err := i.Renew(r.Context(), r.PathValue("id"), q)
		w.Header().Set("cache-control", "no-store")
		reply(w, 201, c, err)
	})
	mux.HandleFunc("PUT /v1/cards/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Status string }
		if !decode(w, r, &q) {
			return
		}
		c, err := i.SetStatus(r.Context(), r.PathValue("id"), q.Status)
		reply(w, 200, c, err)
	})
	mux.HandleFunc("POST /v1/cards/{id}/pin", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			PINBlock string `json:"pinBlock"`
		}
		if !decode(w, r, &q) {
			return
		}
		reply(w, 200, map[string]string{"status": "PIN set"}, i.SetPIN(r.Context(), r.PathValue("id"), q.PINBlock))
	})
	mux.HandleFunc("POST /v1/cards/{id}/pin/generate", func(w http.ResponseWriter, r *http.Request) {
		v, err := i.GeneratePIN(r.Context(), r.PathValue("id"))
		reply(w, 200, map[string]string{"appPinBlock": v}, err)
	})
	mux.HandleFunc("POST /v1/cards/{id}/pin/reveal", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			AppPublicKey string `json:"appPublicKey"`
		}
		if !decode(w, r, &q) {
			return
		}
		v, err := i.RevealPIN(r.Context(), r.PathValue("id"), q.AppPublicKey)
		w.Header().Set("cache-control", "no-store")
		reply(w, 200, map[string]string{"jwe": v}, err)
	})
	mux.HandleFunc("GET /v1/cards/{id}/dcvv2", func(w http.ResponseWriter, r *http.Request) {
		v, err := i.DynamicCVV2(r.Context(), r.PathValue("id"))
		reply(w, 200, map[string]string{"dcvv2": v}, err)
	})
	mux.HandleFunc("GET /v1/cards/{id}/open-to-buy", func(w http.ResponseWriter, r *http.Request) {
		v, err := i.OpenToBuy(r.Context(), r.PathValue("id"))
		reply(w, 200, map[string]int64{"openToBuyMinor": v}, err)
	})
	mux.HandleFunc("POST /v1/cards/{id}/statements", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			CycleDays int `json:"cycleDays"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&q)
		st, err := i.MakeStatement(r.Context(), r.PathValue("id"), q.CycleDays)
		reply(w, 201, st, err)
	})
	mux.HandleFunc("POST /v1/cards/{id}/statements/latest/grace", func(w http.ResponseWriter, r *http.Request) {
		st, err := i.SettleGrace(r.Context(), r.PathValue("id"))
		reply(w, 200, st, err)
	})
	mux.HandleFunc("POST /v1/authorisations", func(w http.ResponseWriter, r *http.Request) {
		var q AuthRequest
		if !decode(w, r, &q) {
			return
		}
		a, err := i.Authorise(r.Context(), q)
		reply(w, 200, a, err)
	})
	mux.HandleFunc("POST /v1/authorisations/{id}/clear", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			AmountMinor int64  `json:"amountMinor"`
			ICC         string `json:"icc"`
		}
		if !decode(w, r, &q) {
			return
		}
		a, err := i.ClearPresentment(r.Context(), r.PathValue("id"), q.AmountMinor, q.ICC)
		reply(w, 200, a, err)
	})
	mux.HandleFunc("POST /v1/authorisations/{id}/reverse", func(w http.ResponseWriter, r *http.Request) {
		a, err := i.Reverse(r.Context(), r.PathValue("id"))
		reply(w, 200, a, err)
	})
	return mux
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(v); err != nil {
		writeJSON(w, 400, map[string]string{"error": "JSON body required"})
		return false
	}
	return true
}

func reply(w http.ResponseWriter, ok int, v any, err error) {
	switch {
	case errors.Is(err, ErrRateLimited):
		writeJSON(w, 429, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNoPendingPIN):
		writeJSON(w, 410, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNotFound):
		writeJSON(w, 404, map[string]string{"error": "not found"})
	case errors.Is(err, ErrInvalid):
		writeJSON(w, 400, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, 502, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, ok, v)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

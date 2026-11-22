package acs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// CMSClient reads cards from card management over HTTP (today the scheme simulator's card API, GET /v1/cards/{pan};
// card-issuer's when it exists, ADR-024).
type CMSClient struct {
	URL  string
	HTTP *http.Client
}

func NewCMSClient(url string) *CMSClient {
	return &CMSClient{URL: url, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

func (c *CMSClient) Card(ctx context.Context, pan string) (Card, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/cards/"+pan, nil)
	if err != nil {
		return Card{}, false, err
	}
	r, err := c.HTTP.Do(req)
	if err != nil {
		return Card{}, false, err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return Card{}, false, nil
	}
	if r.StatusCode != http.StatusOK {
		return Card{}, false, fmt.Errorf("CMS: HTTP %d", r.StatusCode)
	}
	var card Card
	err = json.NewDecoder(r.Body).Decode(&struct {
		Expiry *string `json:"expiry"`
		Status *string `json:"status"`
		Holder *string `json:"holder"`
	}{&card.Expiry, &card.Status, &card.Holder})
	return card, err == nil, err
}

// DSClient posts RReqs to the directory server (which relays them to the 3DS Server).
type DSClient struct {
	URL  string
	HTTP *http.Client
}

func NewDSClient(url string) *DSClient {
	return &DSClient{URL: url, HTTP: &http.Client{Timeout: 3 * time.Second}}
}

func (d *DSClient) Send(ctx context.Context, rr RReq) error {
	if d.URL == "" {
		return nil
	}
	b, _ := json.Marshal(rr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	r, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("DS: HTTP %d", r.StatusCode)
	}
	return nil
}

// LogOTP is the development passcode channel: it logs the code with the masked card number. Production delivers
// it through the notification service (SMS / app push) and never logs it.
type LogOTP struct{}

func (LogOTP) Send(_ context.Context, pan string, _ Card, otp string) error {
	slog.Warn("3ds DEV passcode (never in production)", "card", pan[:6]+"******"+pan[len(pan)-4:], "otp", otp)
	return nil
}

// Handler serves POST /3ds/areq, POST /3ds/creq and GET /healthz.
func (a *ACS) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /3ds/areq", func(w http.ResponseWriter, r *http.Request) {
		var q AReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": "AReq JSON required"})
			return
		}
		res, err := a.Authenticate(r.Context(), q)
		reply(w, res, err)
	})
	mux.HandleFunc("POST /3ds/creq", func(w http.ResponseWriter, r *http.Request) {
		var q CReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": "CReq JSON required"})
			return
		}
		res, err := a.Challenge(r.Context(), q)
		reply(w, res, err)
	})
	return mux
}

func reply(w http.ResponseWriter, res any, err error) {
	switch {
	case errors.Is(err, ErrBadRequest):
		writeJSON(w, 400, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, 500, map[string]string{"error": "internal error"})
	default:
		writeJSON(w, 200, res)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

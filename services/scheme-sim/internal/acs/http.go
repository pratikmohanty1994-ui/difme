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
	"strings"
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
		Expiry   *string   `json:"expiry"`
		Status   *string   `json:"status"`
		Holder   *string   `json:"holder"`
		Channels *[]string `json:"channels"`
	}{&card.Expiry, &card.Status, &card.Holder, &card.Channels})
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

func (LogOTP) Send(_ context.Context, pan string, _ Card, channel, otp string) error {
	slog.Warn("3ds DEV passcode (never in production)", "card", mask(pan), "channel", channel, "otp", otp)
	return nil
}

// LogOOB is the development app-push channel: it logs the request; approve it with POST /3ds/oob/{acsTransID}.
type LogOOB struct{}

func (LogOOB) Notify(_ context.Context, pan, acsTransID, merchant string, amountMinor int64, currency string) error {
	slog.Warn("3ds DEV app push (never in production)", "card", mask(pan), "acsTransID", acsTransID, "merchant", merchant, "amount", amountMinor, "currency", currency)
	return nil
}

func mask(pan string) string { return pan[:6] + "******" + pan[len(pan)-4:] }

// Handler serves POST /3ds/areq, POST /3ds/creq (app, JSON), POST /3ds/challenge (browser, HTML),
// POST /3ds/oob/{acsTransID} (DIFME app's answer: {"approved":true}) and GET /healthz.
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
		if strings.HasPrefix(r.Header.Get("content-type"), "application/jose") { // app channel: JWE in, JWE out
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			out, err := a.AppChallenge(r.Context(), strings.TrimSpace(string(b)))
			if err != nil {
				reply(w, nil, err)
				return
			}
			w.Header().Set("content-type", "application/jose; charset=UTF-8")
			_, _ = w.Write([]byte(out))
			return
		}
		var q CReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": "CReq JSON required"})
			return
		}
		res, err := a.Challenge(r.Context(), q)
		reply(w, res, err)
	})
	mux.HandleFunc("POST /3ds/oob/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Approved bool `json:"approved"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "{\"approved\": bool} required"})
			return
		}
		reply(w, map[string]string{"status": "recorded"}, a.OOBResult(r.Context(), r.PathValue("id"), in.Approved))
	})
	mux.HandleFunc("POST /3ds/challenge", a.browserChallenge)
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

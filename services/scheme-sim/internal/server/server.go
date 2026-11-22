// Package server exposes the simulated network: ISO 8583 over TCP for acquirers/adapters, and an HTTP admin API to
// manage test cards and issuer outages and to inspect processed messages.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/scheme"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

// ServeISO accepts connections and answers framed messages until the listener closes.
func ServeISO(l net.Listener, n *scheme.Network) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleConn(c, n)
	}
}

func handleConn(c net.Conn, n *scheme.Network) {
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute)) // idle links are dropped; echo tests keep them alive
		req, err := wire.Read(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("iso: %s: %v", c.RemoteAddr(), err)
			}
			return
		}
		resp, err := n.Handle(req)
		if err != nil {
			log.Printf("iso: %v", err)
			continue
		}
		if err := wire.Write(c, resp); err != nil {
			return
		}
	}
}

// Admin is the HTTP API: /healthz, /v1/cards, /v1/cards/{pan}, /v1/issuers/{bin}, /v1/transactions.
func Admin(n *scheme.Network) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /v1/cards", func(w http.ResponseWriter, r *http.Request) {
		var c scheme.Card
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&c); err != nil {
			writeJSON(w, 400, map[string]string{"error": "a card body is required"})
			return
		}
		if err := n.PutCard(c); err != nil {
			writeJSON(w, 422, map[string]string{"error": err.Error()})
			return
		}
		got, _ := n.Card(c.PAN)
		writeJSON(w, 201, masked(got))
	})
	mux.HandleFunc("GET /v1/cards/{pan}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := n.Card(r.PathValue("pan"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "unknown card"})
			return
		}
		writeJSON(w, 200, masked(c))
	})
	mux.HandleFunc("PUT /v1/issuers/{bin}", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Down bool `json:"down"`
		}
		bin := r.PathValue("bin")
		if len(bin) != 6 || strings.Trim(bin, "0123456789") != "" || json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "a 6-digit BIN and {\"down\": true|false} are required"})
			return
		}
		n.SetIssuerDown(bin, b.Down)
		writeJSON(w, 200, map[string]any{"bin": bin, "down": b.Down})
	})
	// Token service (ADR-024). Provision returns the token and the masked card, never the card number.
	mux.HandleFunc("POST /v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ PAN, Requestor string }
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pan and requestor are required"})
			return
		}
		if _, ok := n.Card(b.PAN); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown card"})
			return
		}
		t, err := n.Tokens.Provision(b.PAN, b.Requestor)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"token": t.Number, "requestor": t.Requestor, "status": t.Status, "pan": scheme.Mask(b.PAN)})
	})
	mux.HandleFunc("POST /v1/tokens/{token}/cryptogram", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Requestor   string
			AmountMinor int64
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b) != nil || b.AmountMinor <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestor and a positive amountMinor are required"})
			return
		}
		cg, err := n.Tokens.Cryptogram(r.PathValue("token"), b.Requestor, b.AmountMinor)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cryptogram": cg})
	})
	mux.HandleFunc("PUT /v1/tokens/{token}/status", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Status string }
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&b) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status is required"})
			return
		}
		if err := n.Tokens.SetStatus(r.PathValue("token"), b.Status); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": b.Status})
	})
	mux.HandleFunc("GET /v1/transactions", func(w http.ResponseWriter, r *http.Request) {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil || limit < 1 || limit > 1000 {
			limit = 100
		}
		writeJSON(w, 200, map[string]any{"transactions": n.Transactions(limit)})
	})
	return mux
}

func masked(c scheme.Card) scheme.Card {
	c.PAN = scheme.Mask(c.PAN)
	return c
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

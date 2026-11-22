// Package adapter is DIFME's ISO 8583 adapter: services speak JSON over HTTP, the adapter speaks ISO 8583 to the card
// network (here the scheme simulator; a real acquirer link later). One TCP link, multiplexed: responses are matched
// to requests by STAN, so concurrent calls don't wait on each other.
package adapter

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/moov-io/iso8583"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

// Client holds the link to the network and matches responses by STAN.
type Client struct {
	addr    string
	timeout time.Duration

	mu      sync.Mutex // guards conn and writes
	conn    net.Conn
	pending sync.Map // STAN -> chan *iso8583.Message
	stan    uint32
}

func NewClient(addr string, timeout time.Duration) *Client {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &Client{addr: addr, timeout: timeout, stan: binary.BigEndian.Uint32(b[:]) % 900000}
}

func (c *Client) nextSTAN() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stan = c.stan%999999 + 1
	return fmt.Sprintf("%06d", c.stan)
}

// Send writes a request (field 11 must be set) and waits for the response with the same STAN.
func (c *Client) Send(req *iso8583.Message) (*iso8583.Message, error) {
	stan := wire.Get(req, 11)
	ch := make(chan *iso8583.Message, 1)
	c.pending.Store(stan, ch)
	defer c.pending.Delete(stan)
	if err := c.write(req); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(c.timeout):
		return nil, errors.New("no response from the network in time")
	}
}

func (c *Client) write(m *iso8583.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil {
			conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
			if err != nil {
				return fmt.Errorf("network unreachable: %w", err)
			}
			c.conn = conn
			go c.readLoop(conn)
		}
		if err := wire.Write(c.conn, m); err == nil {
			return nil
		}
		_ = c.conn.Close() // broken link: redial once
		c.conn = nil
	}
	return errors.New("network link failed")
}

func (c *Client) readLoop(conn net.Conn) {
	for {
		m, err := wire.Read(conn)
		if err != nil {
			c.mu.Lock()
			if c.conn == conn {
				c.conn = nil
			}
			c.mu.Unlock()
			_ = conn.Close()
			return
		}
		if ch, ok := c.pending.Load(wire.Get(m, 11)); ok {
			ch.(chan *iso8583.Message) <- m
		}
	}
}

// AuthRequest is what a service sends to authorise or buy (amounts in minor units).
type AuthRequest struct {
	PAN         string `json:"pan"`
	Expiry      string `json:"expiry"` // YYMM
	AmountMinor int64  `json:"amountMinor"`
	Currency    string `json:"currency"` // ISO 4217 numeric, default 356 (INR)
	MCC         string `json:"mcc"`
	MerchantID  string `json:"merchantId"`
	TerminalID  string `json:"terminalId"`
	Capture     bool   `json:"capture"`        // true: 0200 purchase, false: 0100 authorisation only
	CAVV        string `json:"cavv,omitempty"` // 3-D Secure authenticationValue from the ACS (field 48 "CAVV:", ADR-027)
}

// AuthResult is the network's answer.
type AuthResult struct {
	Approved     bool   `json:"approved"`
	ResponseCode string `json:"responseCode"`
	AuthCode     string `json:"authCode,omitempty"`
	RRN          string `json:"rrn"`
	STAN         string `json:"stan"`
}

// Authorise sends 0100 (or 0200 with Capture) and returns the outcome.
func (c *Client) Authorise(a AuthRequest) (AuthResult, error) {
	if a.Currency == "" {
		a.Currency = "356"
	}
	if a.TerminalID == "" {
		a.TerminalID = "DIFME001"
	}
	now := time.Now().UTC()
	stan := c.nextSTAN()
	m := iso8583.NewMessage(wire.Spec)
	if a.Capture {
		m.MTI("0200")
	} else {
		m.MTI("0100")
	}
	for f, v := range map[int]string{
		2: a.PAN, 3: "000000", 4: fmt.Sprintf("%012d", a.AmountMinor), 7: now.Format("0102150405"), 11: stan,
		12: now.Format("150405"), 13: now.Format("0102"), 14: a.Expiry, 18: a.MCC, 22: "810", // 81x: e-commerce / agent-initiated
		41: fmt.Sprintf("%-8.8s", a.TerminalID), 42: fmt.Sprintf("%-15.15s", a.MerchantID), 49: a.Currency, 48: cavvField(a.CAVV),
	} {
		if v != "" {
			if err := m.Field(f, v); err != nil {
				return AuthResult{}, fmt.Errorf("field %d: %w", f, err)
			}
		}
	}
	resp, err := c.Send(m)
	if err != nil {
		return AuthResult{}, err
	}
	rc := wire.Get(resp, 39)
	return AuthResult{Approved: rc == "00", ResponseCode: rc, AuthCode: wire.Get(resp, 38), RRN: wire.Get(resp, 37), STAN: stan}, nil
}

// Reverse sends 0400 for an earlier approval (by its RRN); the network releases the hold.
func (c *Client) Reverse(rrn string, amountMinor int64) (AuthResult, error) {
	now := time.Now().UTC()
	stan := c.nextSTAN()
	m := iso8583.NewMessage(wire.Spec)
	m.MTI("0400")
	for f, v := range map[int]string{4: fmt.Sprintf("%012d", amountMinor), 7: now.Format("0102150405"), 11: stan, 37: rrn} {
		if err := m.Field(f, v); err != nil {
			return AuthResult{}, err
		}
	}
	resp, err := c.Send(m)
	if err != nil {
		return AuthResult{}, err
	}
	rc := wire.Get(resp, 39)
	return AuthResult{Approved: rc == "00", ResponseCode: rc, RRN: rrn, STAN: stan}, nil
}

// Refund sends a 0200 credit (processing code 200000) for part or all of an earlier purchase, identified by its RRN.
func (c *Client) Refund(origRRN, pan string, amountMinor int64, currency, merchantID string) (AuthResult, error) {
	if currency == "" {
		currency = "356"
	}
	now := time.Now().UTC()
	stan := c.nextSTAN()
	m := iso8583.NewMessage(wire.Spec)
	m.MTI("0200")
	for f, v := range map[int]string{2: pan, 3: "200000", 4: fmt.Sprintf("%012d", amountMinor), 7: now.Format("0102150405"),
		11: stan, 37: origRRN, 41: fmt.Sprintf("%-8.8s", "DIFME001"), 42: fmt.Sprintf("%-15.15s", merchantID), 49: currency} {
		if err := m.Field(f, v); err != nil {
			return AuthResult{}, fmt.Errorf("field %d: %w", f, err)
		}
	}
	resp, err := c.Send(m)
	if err != nil {
		return AuthResult{}, err
	}
	rc := wire.Get(resp, 39)
	return AuthResult{Approved: rc == "00", ResponseCode: rc, AuthCode: wire.Get(resp, 38), RRN: wire.Get(resp, 37), STAN: stan}, nil
}

// Echo sends 0800 (network management) to check the link.
func (c *Client) Echo() error {
	m := iso8583.NewMessage(wire.Spec)
	m.MTI("0800")
	_ = m.Field(7, time.Now().UTC().Format("0102150405"))
	_ = m.Field(11, c.nextSTAN())
	resp, err := c.Send(m)
	if err != nil {
		return err
	}
	if wire.Get(resp, 39) != "00" {
		return errors.New("echo declined")
	}
	return nil
}

// HTTP is the adapter's JSON API: POST /v1/authorize, POST /v1/reverse, GET /healthz (echo test to the network).
func HTTP(c *Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := c.Echo(); err != nil {
			writeJSON(w, 503, map[string]string{"error": err.Error()})
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var a AuthRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&a); err != nil || a.PAN == "" || a.AmountMinor <= 0 {
			writeJSON(w, 400, map[string]string{"error": "pan and a positive amountMinor are required"})
			return
		}
		res, err := c.Authorise(a)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("POST /v1/reverse", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			RRN         string `json:"rrn"`
			AmountMinor int64  `json:"amountMinor"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&b); err != nil || b.RRN == "" {
			writeJSON(w, 400, map[string]string{"error": "rrn is required"})
			return
		}
		res, err := c.Reverse(b.RRN, b.AmountMinor)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, res)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func cavvField(v string) string {
	if v == "" {
		return ""
	}
	return "CAVV:" + v
}

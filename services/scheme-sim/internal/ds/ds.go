// Package ds is DIFME's EMV 3DS 2.3.1 directory server simulator (ADR-027): the scheme's hop between a 3DS Server and
// the issuers' ACSs.
//
//   - AReq (POST /3ds/areq, from the 3DS Server): the DS assigns dsTransID and adds dsReferenceNumber and dsURL,
//     routes by card range (longest BIN prefix → the ACS's AReq URL), forwards, and returns the ACS's ARes.
//   - Stand-in: when the card range is not enrolled (no range matches) or the ACS cannot be reached (network error,
//     timeout, 5xx, unreadable ARes), the DS answers itself with transStatus "A" (attempts) and an attempts CAVV
//     (result code 7, ECI 06) computed by the security module, so the merchant still gets liability shift.
//   - RReq (POST /3ds/rreq, from the ACS): relayed to the 3DS Server's threeDSServerURL taken from the AReq of the same
//     dsTransID; the 3DS Server's RRes goes back to the ACS.
//
// Messages are relayed as JSON objects so fields this simulator does not model pass through unchanged. Transactions
// (dsTransID → threeDSServerURL) are kept in memory.
package ds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

// Range maps a card range (BIN prefix, 6–19 digits) to the issuer ACS's AReq URL.
type Range struct {
	Prefix string `json:"prefix"`
	ACSURL string `json:"acsURL"`
}

// ParseRanges reads the card-range table, a JSON array of {"prefix","acsURL"}.
func ParseRanges(b []byte) ([]Range, error) {
	var rs []Range
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("card ranges: %w", err)
	}
	for _, r := range rs {
		if r.Prefix == "" || strings.Trim(r.Prefix, "0123456789") != "" || len(r.Prefix) > 19 {
			return nil, fmt.Errorf("card ranges: prefix %q must be digits", r.Prefix)
		}
		if !strings.HasPrefix(r.ACSURL, "http://") && !strings.HasPrefix(r.ACSURL, "https://") {
			return nil, fmt.Errorf("card ranges: acsURL %q for %s must be http(s)", r.ACSURL, r.Prefix)
		}
	}
	return rs, nil
}

type Config struct {
	Ranges    []Range
	HSM       threeds.HSM  // security module: attempts CAVVs for stand-in
	Reference string       // dsReferenceNumber
	URL       string       // dsURL: where ACSs post RReqs
	HTTP      *http.Client // to ACSs and 3DS Servers
	TxTTL     time.Duration
	Now       func() time.Time
}

type tx struct {
	serverURL string
	expires   time.Time
}

type DS struct {
	cfg Config
	mu  sync.Mutex
	txs map[string]tx // dsTransID → 3DS Server results URL
}

func New(cfg Config) *DS {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.TxTTL == 0 {
		cfg.TxTTL = 24 * time.Hour // covers decoupled authentications
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Reference == "" {
		cfg.Reference = "DIFME-DS-SIM"
	}
	rs := slices.Clone(cfg.Ranges)
	slices.SortStableFunc(rs, func(a, b Range) int { return len(b.Prefix) - len(a.Prefix) }) // longest prefix first
	cfg.Ranges = rs
	return &DS{cfg: cfg, txs: map[string]tx{}}
}

// Route returns the ACS AReq URL for a card number ("" when its range is not enrolled).
func (d *DS) Route(pan string) string {
	for _, r := range d.cfg.Ranges {
		if strings.HasPrefix(pan, r.Prefix) {
			return r.ACSURL
		}
	}
	return ""
}

// ErrBadRequest marks a message the DS refuses (HTTP 400).
var ErrBadRequest = errors.New("bad request")

// Versions the DS accepts.
var Versions = []string{"2.3.1", "2.2.0"}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func isHTTP(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// AReq handles an authentication request from a 3DS Server and returns the ARes (as JSON object) and the HTTP status.
func (d *DS) AReq(ctx context.Context, q map[string]any) (map[string]any, int, error) {
	pan := str(q, "acctNumber")
	switch {
	case str(q, "messageType") != "AReq" || str(q, "threeDSServerTransID") == "":
		return nil, 0, fmt.Errorf("%w: AReq needs messageType and threeDSServerTransID", ErrBadRequest)
	case !slices.Contains(Versions, str(q, "messageVersion")):
		return nil, 0, fmt.Errorf("%w: messageVersion %q not supported (%v)", ErrBadRequest, str(q, "messageVersion"), Versions)
	case len(pan) < 12 || len(pan) > 19 || strings.Trim(pan, "0123456789") != "":
		return nil, 0, fmt.Errorf("%w: acctNumber", ErrBadRequest)
	case !isHTTP(str(q, "threeDSServerURL")):
		return nil, 0, fmt.Errorf("%w: threeDSServerURL (http/https) required for the RReq", ErrBadRequest)
	}
	dsID := newID()
	q["dsTransID"], q["dsReferenceNumber"] = dsID, d.cfg.Reference
	if d.cfg.URL != "" {
		q["dsURL"] = d.cfg.URL
	}
	d.remember(dsID, str(q, "threeDSServerURL"))

	acsURL := d.Route(pan)
	if acsURL == "" {
		slog.Info("ds: card range not enrolled, stand-in", "dsTransID", dsID, "bin", pan[:6])
		return d.standIn(ctx, q, dsID), http.StatusOK, nil
	}
	res, status, err := d.post(ctx, acsURL, q)
	switch {
	case err != nil || status >= 500:
		slog.Warn("ds: ACS unreachable, stand-in", "dsTransID", dsID, "acs", acsURL, "status", status, "err", err)
		return d.standIn(ctx, q, dsID), http.StatusOK, nil
	case status != http.StatusOK:
		d.forget(dsID)
		return res, status, nil // the ACS refused the message: its error goes back as is
	}
	res["dsTransID"], res["dsReferenceNumber"] = dsID, d.cfg.Reference
	slog.Info("ds: ARes", "dsTransID", dsID, "acsTransID", str(res, "acsTransID"), "transStatus", str(res, "transStatus"))
	if ts := str(res, "transStatus"); ts != "C" && ts != "D" {
		d.forget(dsID) // no RReq will follow
	}
	return res, http.StatusOK, nil
}

// standIn is the DS's attempts response (transStatus A, attempts CAVV, ECI 06). If the security module cannot
// compute the CAVV, the answer is U.
func (d *DS) standIn(ctx context.Context, q map[string]any, dsID string) map[string]any {
	d.forget(dsID)
	res := map[string]any{"messageType": "ARes", "messageVersion": str(q, "messageVersion"), "threeDSServerTransID": str(q, "threeDSServerTransID"),
		"dsTransID": dsID, "dsReferenceNumber": d.cfg.Reference, "acsTransID": newID()}
	if v := str(q, "sdkTransID"); v != "" {
		res["sdkTransID"] = v
	}
	cavv, _, err := threeds.Build(ctx, d.cfg.HSM, str(q, "acctNumber"), threeds.ResultAttempt, 0)
	if err != nil {
		slog.Error("ds: security module (attempts CAVV)", "dsTransID", dsID, "err", err)
		res["transStatus"], res["transStatusReason"] = "U", "09" // security failure
		return res
	}
	res["transStatus"], res["authenticationValue"], res["eci"] = "A", cavv, "06"
	return res
}

// RReq relays an ACS's results request to the 3DS Server of the same dsTransID and returns its RRes.
func (d *DS) RReq(ctx context.Context, rr map[string]any) (map[string]any, int, error) {
	id := str(rr, "dsTransID")
	if str(rr, "messageType") != "RReq" || id == "" {
		return nil, 0, fmt.Errorf("%w: RReq needs messageType and dsTransID", ErrBadRequest)
	}
	d.mu.Lock()
	t, ok := d.txs[id]
	d.mu.Unlock()
	if !ok || d.cfg.Now().After(t.expires) {
		return nil, 0, fmt.Errorf("%w: unknown dsTransID", ErrBadRequest)
	}
	res, status, err := d.post(ctx, t.serverURL, rr)
	if err != nil {
		slog.Error("ds: RReq relay", "dsTransID", id, "err", err)
		return nil, http.StatusBadGateway, nil
	}
	if status == http.StatusOK {
		d.forget(id)
	}
	slog.Info("ds: RReq relayed", "dsTransID", id, "transStatus", str(rr, "transStatus"), "status", status)
	return res, status, nil
}

func (d *DS) remember(id, serverURL string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.cfg.Now()
	for k, t := range d.txs {
		if now.After(t.expires) {
			delete(d.txs, k)
		}
	}
	d.txs[id] = tx{serverURL: serverURL, expires: now.Add(d.cfg.TxTTL)}
}

func (d *DS) forget(id string) {
	d.mu.Lock()
	delete(d.txs, id)
	d.mu.Unlock()
}

func (d *DS) post(ctx context.Context, url string, body map[string]any) (map[string]any, int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("content-type", "application/json")
	r, err := d.cfg.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&out); err != nil {
		if r.StatusCode == http.StatusOK {
			return nil, 0, fmt.Errorf("%s: unreadable response: %w", url, err)
		}
		out = map[string]any{"error": fmt.Sprintf("HTTP %d", r.StatusCode)}
	}
	return out, r.StatusCode, nil
}

// Handler serves POST /3ds/areq (3DS Server), POST /3ds/rreq (ACS) and GET /healthz.
func (d *DS) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	serve := func(h func(context.Context, map[string]any) (map[string]any, int, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var in map[string]any
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in == nil {
				writeJSON(w, 400, map[string]string{"error": "JSON object required"})
				return
			}
			out, status, err := h(r.Context(), in)
			switch {
			case errors.Is(err, ErrBadRequest):
				writeJSON(w, 400, map[string]string{"error": err.Error()})
			case err != nil:
				writeJSON(w, 500, map[string]string{"error": "internal error"})
			case out == nil:
				writeJSON(w, status, map[string]string{"error": http.StatusText(status)})
			default:
				writeJSON(w, status, out)
			}
		}
	}
	mux.HandleFunc("POST /3ds/areq", serve(d.AReq))
	mux.HandleFunc("POST /3ds/rreq", serve(d.RReq))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

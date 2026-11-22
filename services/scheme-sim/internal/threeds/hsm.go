package threeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HSM is the security module's CAVV functions (services/hsm, ADR-026).
type HSM interface {
	CAVV(ctx context.Context, pan, upn, authrc, sfarc string) (string, error)
	VerifyCAVV(ctx context.Context, pan, cvv, upn, authrc, sfarc string) (bool, error)
}

// HSMClient calls services/hsm over HTTP (mTLS is the mesh's).
type HSMClient struct {
	URL  string
	HTTP *http.Client
}

func NewHSMClient(url string) *HSMClient {
	return &HSMClient{URL: url, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

func (h *HSMClient) call(ctx context.Context, path string, in map[string]string) (map[string]string, error) {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	r, err := h.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm %s: HTTP %d %s", path, r.StatusCode, out["error"])
	}
	return out, nil
}

func (h *HSMClient) CAVV(ctx context.Context, pan, upn, authrc, sfarc string) (string, error) {
	out, err := h.call(ctx, "/v1/cavv", map[string]string{"pan": pan, "upn": upn, "authrc": authrc, "sfarc": sfarc})
	if err != nil {
		return "", err
	}
	return out["cavv"], nil
}

func (h *HSMClient) VerifyCAVV(ctx context.Context, pan, cvv, upn, authrc, sfarc string) (bool, error) {
	out, err := h.call(ctx, "/v1/cavv/verify", map[string]string{"pan": pan, "cavv": cvv, "upn": upn, "authrc": authrc, "sfarc": sfarc})
	if err != nil {
		return false, err
	}
	return out["valid"] == "true", nil
}

// Build asks the security module for the cryptographic part and returns the encoded CAVV.
func Build(ctx context.Context, h HSM, pan string, result, secondFactor int) (string, CAVV, error) {
	c := CAVV{Result: result, SecondFactor: secondFactor, KeyIndicator: KeyIndicator, ATN: NewATN(), ECI: ECIFor(result)}
	cvv, err := h.CAVV(ctx, pan, c.UPN(), c.AuthRC(), c.SFARC())
	if err != nil {
		return "", c, err
	}
	c.CVV = cvv
	return c.Encode(), c, nil
}

// Verify decodes a CAVV and checks its cryptogram with the security module. Replay (ATN reuse) is the caller's check.
func Verify(ctx context.Context, h HSM, pan, value string) (CAVV, error) {
	c, err := Decode(value)
	if err != nil {
		return c, err
	}
	if c.KeyIndicator != KeyIndicator {
		return c, fmt.Errorf("%w: unknown key indicator %d", ErrFormat, c.KeyIndicator)
	}
	ok, err := h.VerifyCAVV(ctx, pan, c.CVV, c.UPN(), c.AuthRC(), c.SFARC())
	if err != nil {
		return c, err
	}
	if !ok {
		return c, ErrCryptogram
	}
	return c, nil
}

var ErrCryptogram = fmt.Errorf("CAVV cryptogram invalid")

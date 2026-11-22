package issuer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HSMClient calls services/hsm (keys by label: cvk, dcvv2, zpk, pvk, aes-pin). The mesh authorises this caller.
type HSMClient struct {
	URL  string
	HTTP *http.Client
	PVKI string // PVV key index
}

func NewHSMClient(url string) *HSMClient {
	return &HSMClient{URL: url, HTTP: &http.Client{Timeout: 3 * time.Second}, PVKI: "1"}
}

func (h *HSMClient) call(ctx context.Context, path string, in map[string]string, field string) (string, error) {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.URL+path, bytes.NewReader(b))
	req.Header.Set("content-type", "application/json")
	r, err := h.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 {
		return "", fmt.Errorf("hsm %s: HTTP %d %s", path, r.StatusCode, out["error"])
	}
	return out[field], nil
}

func (h *HSMClient) CVV2(ctx context.Context, pan, expiry string) (string, error) {
	return h.call(ctx, "/v1/cvv2", map[string]string{"pan": pan, "expiry": expiry}, "cvv2")
}

func (h *HSMClient) VerifyCVV2(ctx context.Context, pan, expiry, cvv2 string) (bool, error) {
	v, err := h.call(ctx, "/v1/cvv2/verify", map[string]string{"pan": pan, "expiry": expiry, "cvv2": cvv2}, "valid")
	return v == "true", err
}

func (h *HSMClient) DCVV2(ctx context.Context, pan string) (string, error) {
	return h.call(ctx, "/v1/dcvv2", map[string]string{"pan": pan}, "code")
}

func (h *HSMClient) VerifyDCVV2(ctx context.Context, pan, code string) (bool, error) {
	v, err := h.call(ctx, "/v1/dcvv2/verify", map[string]string{"pan": pan, "code": code}, "valid")
	return v == "true", err
}

func (h *HSMClient) PINFromApp(ctx context.Context, pan, iso4Hex string) (string, error) {
	return h.call(ctx, "/v1/pin/iso4-to-zpk", map[string]string{"pan": pan, "pinBlock": iso4Hex}, "pinBlock")
}

func (h *HSMClient) PVV(ctx context.Context, pan, block string) (string, error) {
	return h.call(ctx, "/v1/pin/pvv", map[string]string{"pan": pan, "pinBlock": block, "pvki": h.PVKI}, "pvv")
}

func (h *HSMClient) VerifyPVV(ctx context.Context, pan, block, pvv string) (bool, error) {
	v, err := h.call(ctx, "/v1/pin/verify-pvv", map[string]string{"pan": pan, "pinBlock": block, "pvki": h.PVKI, "pvv": pvv}, "valid")
	return v == "true", err
}

// Index, Seal and Open make HSMClient the card vault (keys card-index and card-vault in the security module).
func (h *HSMClient) Index(ctx context.Context, pan string) (string, error) {
	return h.call(ctx, "/v1/hmac", map[string]string{"key": "card-index", "data": hex.EncodeToString([]byte("pan|" + pan))}, "mac")
}

func (h *HSMClient) Seal(ctx context.Context, cardID, pan string) (string, error) {
	return h.call(ctx, "/v1/data/encrypt", map[string]string{"key": "card-vault", "data": hex.EncodeToString([]byte(pan)),
		"aad": hex.EncodeToString([]byte(cardID))}, "ciphertext")
}

func (h *HSMClient) Open(ctx context.Context, cardID, sealed string) (string, error) {
	v, err := h.call(ctx, "/v1/data/decrypt", map[string]string{"key": "card-vault", "ciphertext": sealed, "aad": hex.EncodeToString([]byte(cardID))}, "data")
	if err != nil {
		return "", err
	}
	b, err := hex.DecodeString(v)
	return string(b), err
}

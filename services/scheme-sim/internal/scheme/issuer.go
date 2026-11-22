package scheme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// IssuerRequest is the network's authorisation request to an issuer host.
type IssuerRequest struct {
	PAN         string `json:"pan"`
	Expiry      string `json:"expiry,omitempty"`
	AmountMinor int64  `json:"amountMinor"`
	Currency    string `json:"currency"`
	Merchant    string `json:"merchant"`
	CVV2        string `json:"cvv2,omitempty"`
	PINBlock    string `json:"pinBlock,omitempty"`
}

// Issuer is an issuer host (services/card-issuer).
type Issuer interface {
	Authorise(ctx context.Context, r IssuerRequest) (code, authID string, err error)
	Clear(ctx context.Context, authID string, amountMinor int64) error
	Reverse(ctx context.Context, authID string) error
}

// IssuerClient calls card-issuer's HTTP API.
type IssuerClient struct {
	URL  string
	HTTP *http.Client
}

func NewIssuerClient(url string) *IssuerClient {
	return &IssuerClient{URL: url, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (c *IssuerClient) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(b))
	req.Header.Set("content-type", "application/json")
	r, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("issuer %s: HTTP %d", path, r.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}

func (c *IssuerClient) Authorise(ctx context.Context, r IssuerRequest) (string, string, error) {
	var a struct {
		ID   string `json:"id"`
		Code string `json:"responseCode"`
	}
	if err := c.post(ctx, "/v1/authorisations", r, &a); err != nil {
		return "", "", err
	}
	return a.Code, a.ID, nil
}

func (c *IssuerClient) Clear(ctx context.Context, id string, amountMinor int64) error {
	return c.post(ctx, "/v1/authorisations/"+id+"/clear", map[string]int64{"amountMinor": amountMinor}, nil)
}

func (c *IssuerClient) Reverse(ctx context.Context, id string) error {
	return c.post(ctx, "/v1/authorisations/"+id+"/reverse", map[string]string{}, nil)
}

package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Fineract is the Ledger on Apache Fineract's REST API (tenant "default"). Auth: a Keycloak client-credentials token
// (TokenURL, ClientID, ClientSecret) in the cluster, or basic auth (User, Password) against a local test server.
type Fineract struct {
	BaseURL, Tenant                  string
	TokenURL, ClientID, ClientSecret string
	User, Password                   string
	PaymentTypeID                    int64 // Fineract payment type for card withdrawals ("Card network")
	HTTP                             *http.Client
	mu                               sync.Mutex
	token                            string
	tokenExp                         time.Time
}

const dateFmt = "02 January 2006"

func money(minor int64) string { return fmt.Sprintf("%d.%02d", minor/100, minor%100) }

func (f *Fineract) bearer(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token != "" && time.Now().Before(f.tokenExp) {
		return f.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {f.ClientID}, "client_secret": {f.ClientSecret}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	r, err := f.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil || t.AccessToken == "" {
		return "", fmt.Errorf("keycloak token: HTTP %d", r.StatusCode)
	}
	f.token, f.tokenExp = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn-30)*time.Second)
	return f.token, nil
}

func (f *Fineract) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.BaseURL+"/api/v1/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Fineract-Platform-TenantId", f.Tenant)
	req.Header.Set("content-type", "application/json")
	if f.TokenURL != "" {
		t, err := f.bearer(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+t)
	} else {
		req.SetBasicAuth(f.User, f.Password)
	}
	r, err := f.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode != 200 {
		var e struct {
			Errors []struct{ DefaultUserMessage string }
		}
		_ = json.Unmarshal(b, &e)
		msg := string(b)
		if len(e.Errors) > 0 {
			msg = e.Errors[0].DefaultUserMessage
		}
		return fmt.Errorf("fineract %s %s: HTTP %d %s", method, path, r.StatusCode, msg)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func minor(v float64) int64 { return int64(math.Round(v * 100)) }

func (f *Fineract) Available(ctx context.Context, savings int64) (int64, error) {
	var a struct {
		Summary struct {
			AvailableBalance *float64 `json:"availableBalance"`
			AccountBalance   float64  `json:"accountBalance"`
			TotalOnHold      float64  `json:"totalOnHoldAmount"`
		} `json:"summary"`
	}
	if err := f.call(ctx, http.MethodGet, fmt.Sprintf("savingsaccounts/%d", savings), nil, &a); err != nil {
		return 0, err
	}
	if a.Summary.AvailableBalance != nil {
		return minor(*a.Summary.AvailableBalance), nil
	}
	return minor(a.Summary.AccountBalance - a.Summary.TotalOnHold), nil
}

func (f *Fineract) today() map[string]any {
	return map[string]any{"locale": "en", "dateFormat": "dd MMMM yyyy", "transactionDate": time.Now().Format(dateFmt)}
}

func (f *Fineract) Hold(ctx context.Context, savings, amountMinor int64, reason string) (int64, error) {
	b := f.today()
	b["transactionAmount"], b["reasonForBlock"] = money(amountMinor), reason
	var r struct {
		ResourceID int64 `json:"resourceId"`
	}
	err := f.call(ctx, http.MethodPost, fmt.Sprintf("savingsaccounts/%d/transactions?command=holdAmount", savings), b, &r)
	return r.ResourceID, err
}

func (f *Fineract) Release(ctx context.Context, savings, holdRef int64) error {
	return f.call(ctx, http.MethodPost, fmt.Sprintf("savingsaccounts/%d/transactions/%d?command=releaseAmount", savings, holdRef), map[string]any{}, nil)
}

func (f *Fineract) Withdraw(ctx context.Context, savings, amountMinor int64, note string) error {
	b := f.today()
	b["transactionAmount"], b["note"] = money(amountMinor), note
	if f.PaymentTypeID > 0 {
		b["paymentTypeId"] = f.PaymentTypeID
	}
	return f.call(ctx, http.MethodPost, fmt.Sprintf("savingsaccounts/%d/transactions?command=withdrawal", savings), b, nil)
}

func (f *Fineract) Outstanding(ctx context.Context, loan int64) (int64, error) {
	var l struct {
		Summary *struct {
			PrincipalOutstanding float64 `json:"principalOutstanding"`
		} `json:"summary"`
	}
	if err := f.call(ctx, http.MethodGet, fmt.Sprintf("loans/%d", loan), nil, &l); err != nil {
		return 0, err
	}
	if l.Summary == nil {
		return 0, nil // nothing disbursed yet
	}
	return minor(l.Summary.PrincipalOutstanding), nil
}

func (f *Fineract) Disburse(ctx context.Context, loan, amountMinor int64) error {
	return f.call(ctx, http.MethodPost, fmt.Sprintf("loans/%d?command=disburse", loan), map[string]any{"locale": "en", "dateFormat": "dd MMMM yyyy",
		"actualDisbursementDate": time.Now().Format(dateFmt), "transactionAmount": money(amountMinor)}, nil)
}

package issuer

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// an EC P-256 SubjectPublicKeyInfo prefix (the fake security module only checks it is DER)
var appSPKI = []byte("\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04" + strings.Repeat("\x11", 64))

type auditLog struct {
	mu     sync.Mutex
	events []string
}

func (a *auditLog) record(_ context.Context, event string, attrs ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := []string{event}
	for k := 0; k+1 < len(attrs); k += 2 {
		if v, ok := attrs[k+1].(string); ok {
			b = append(b, attrs[k].(string)+"="+v)
		}
	}
	a.events = append(a.events, strings.Join(b, " "))
}

func TestPINRevealOnceAuditedAndRateLimited(t *testing.T) {
	i, _ := setup(t)
	log := &auditLog{}
	i.Audit = log.record
	ctx := context.Background()
	c, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	key := base64.StdEncoding.EncodeToString(appSPKI)
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrNoPendingPIN) {
		t.Fatalf("nothing generated yet: %v", err)
	}
	if _, err := i.GeneratePIN(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := i.RevealPIN(ctx, c.ID, "not-a-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad key: %v", err)
	}
	jwe, err := i.RevealPIN(ctx, c.ID, key)
	if err != nil || jwe != "jwe(4-app)" {
		t.Fatalf("reveal: %q %v", jwe, err)
	}
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrNoPendingPIN) {
		t.Fatalf("second reveal: %v", err)
	}
	// the revealed PIN still works for payments (its PVV is kept)
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100, PINBlock: "Z48264"}); a.Code != Approved {
		t.Fatalf("PIN after reveal: %+v", a)
	}
	// 5 attempts per hour: 4 used above, the 5th passes the limiter, the 6th is refused
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrNoPendingPIN) {
		t.Fatalf("5th: %v", err)
	}
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("6th attempt: %v", err)
	}
	i.now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrNoPendingPIN) {
		t.Fatalf("after the window: %v", err)
	}
	want := []string{"none_pending", "bad_app_key", "revealed", "none_pending", "none_pending", "rate_limited", "none_pending"}
	if len(log.events) != len(want) {
		t.Fatalf("audit: %q", log.events)
	}
	for k, e := range log.events {
		if !strings.HasPrefix(e, "pin_reveal ") || !strings.Contains(e, "outcome="+want[k]) || strings.Contains(e, c.PANFull) || strings.Contains(e, "8264") {
			t.Errorf("audit %d: %q (want outcome %s, no PAN/PIN)", k, e, want[k])
		}
	}
	// a PIN the cardholder chooses cancels a pending generated one
	_, _ = i.GeneratePIN(ctx, c.ID)
	_ = i.SetPIN(ctx, c.ID, "41234")
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrNoPendingPIN) {
		t.Fatalf("after SetPIN: %v", err)
	}
	// a blocked card reveals nothing
	_, _ = i.GeneratePIN(ctx, c.ID)
	_, _ = i.SetStatus(ctx, c.ID, "BLOCKED")
	if _, err := i.RevealPIN(ctx, c.ID, key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("blocked card: %v", err)
	}
}

func TestPINRevealHTTP(t *testing.T) {
	i, _ := setup(t)
	i.Audit = func(context.Context, string, ...any) {}
	srv := httptest.NewServer(Handler(i))
	defer srv.Close()
	ctx := context.Background()
	c, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	_, _ = i.GeneratePIN(ctx, c.ID)
	post := func(body string) (int, string) {
		r, err := http.Post(srv.URL+"/v1/cards/"+c.ID+"/pin/reveal", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("cache-control") != "no-store" {
			t.Errorf("cache-control %q", r.Header.Get("cache-control"))
		}
		return r.StatusCode, string(b)
	}
	key := base64.RawURLEncoding.EncodeToString(appSPKI)
	if code, _ := post(`{"appPublicKey":"zz"}`); code != 400 {
		t.Errorf("bad key: %d", code)
	}
	if code, body := post(`{"appPublicKey":"` + key + `"}`); code != 200 || !strings.Contains(body, `"jwe":"jwe(4-app)"`) {
		t.Errorf("reveal: %d %s", code, body)
	}
	if code, _ := post(`{"appPublicKey":"` + key + `"}`); code != 410 {
		t.Errorf("second reveal: %d", code)
	}
	for k := 0; k < 3; k++ {
		post(`{"appPublicKey":"` + key + `"}`)
	}
	if code, _ := post(`{"appPublicKey":"` + key + `"}`); code != 429 {
		t.Errorf("rate limit: %d", code)
	}
}

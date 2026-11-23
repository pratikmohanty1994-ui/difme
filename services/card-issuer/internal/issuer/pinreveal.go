package issuer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// One-time PIN reveal (ADR-026): a PIN generated in the security module is shown once in the cardholder's app. The
// clear PIN never leaves the module: card-issuer holds it only as an ISO 4 block under the module's PIN key and asks the
// module to re-encrypt it to the app's public key (JWE, RSA-OAEP-256 or ECDH-ES with A256GCM). After a successful
// reveal the block is deleted, so a second reveal needs a new PIN (GeneratePIN). Every attempt is audited and attempts
// per card are rate limited.

const (
	revealAttempts = 5         // attempts per card ...
	revealWindow   = time.Hour // ... per sliding window
)

var (
	// ErrNoPendingPIN: nothing to reveal (already revealed, or the cardholder chose the PIN).
	ErrNoPendingPIN = errors.New("no PIN pending reveal")
	// ErrRateLimited: too many attempts for this card; try later.
	ErrRateLimited = errors.New("too many attempts")
)

// RevealPIN returns the card's pending PIN encrypted to the app's public key (X.509 SubjectPublicKeyInfo, base64,
// base64url or hex) and deletes the pending PIN.
func (i *Issuer) RevealPIN(ctx context.Context, id, appKey string) (string, error) {
	audit := func(outcome string, c Card) {
		i.Audit(ctx, "pin_reveal", "card", id, "pan", c.MaskedPAN, "outcome", outcome)
	}
	if !i.reveal.allow(id, i.now()) {
		audit("rate_limited", Card{})
		return "", ErrRateLimited
	}
	spki, err := parseAppKey(appKey)
	if err != nil {
		audit("bad_app_key", Card{})
		return "", err
	}
	i.mu.Lock() // one reveal at a time: the pending PIN is used once
	defer i.mu.Unlock()
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return "", err
	}
	if c.Status == "BLOCKED" || c.Status == "REPLACED" {
		audit("card_"+strings.ToLower(c.Status), c)
		return "", fmt.Errorf("%w: card %s", ErrInvalid, strings.ToLower(c.Status))
	}
	if c.PendingPIN == "" {
		audit("none_pending", c)
		return "", ErrNoPendingPIN
	}
	jwe, err := i.hsm.RevealPIN(ctx, c.PAN, c.PendingPIN, spki)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			audit("bad_app_key", c)
		} else {
			audit("hsm_error", c)
		}
		return "", err
	}
	c.PendingPIN = ""
	if err := i.store.PutCard(ctx, c); err != nil {
		audit("store_error", c) // not revealed: the pending PIN is kept for a retry
		return "", err
	}
	audit("revealed", c)
	return jwe, nil
}

// parseAppKey accepts a DER SubjectPublicKeyInfo as base64, base64url or hex and returns it in hex. The module checks
// the key itself (type, size, curve).
func parseAppKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) < 32 || len(s) > 2048 {
		return "", fmt.Errorf("%w: appPublicKey: X.509 SubjectPublicKeyInfo (DER) in base64 or hex", ErrInvalid)
	}
	if b, err := hex.DecodeString(s); err == nil && b[0] == 0x30 {
		return hex.EncodeToString(b), nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 && b[0] == 0x30 {
			return hex.EncodeToString(b), nil
		}
	}
	return "", fmt.Errorf("%w: appPublicKey: X.509 SubjectPublicKeyInfo (DER) in base64 or hex", ErrInvalid)
}

// limiter allows n events per key in a sliding window.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, seen: map[string][]time.Time{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.n {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	return true
}

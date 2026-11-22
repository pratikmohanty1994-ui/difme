// Package tokens is the card network's token service (TSP, ADR-024): network tokens stand in for card numbers at
// merchants and PSPs. A token is bound to one token requestor (a merchant or PSP id) and has a lifecycle
// (ACTIVE, SUSPENDED, DELETED). Each payment carries a single-use cryptogram the TSP issues to that requestor: an HMAC
// over token, requestor, amount and a transaction counter with a per-token key that never leaves the TSP. On an
// authorisation the network swaps the token for the card number before the issuer sees it (Detokenize).
// Simulator scope: the per-token keys are random and held in memory; ADR-026 moves cryptograms to the security module.
package tokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
)

// Token number range: separate from card BINs, so a token can never be mistaken for a card number.
const TokenBIN = "489537"

var (
	ErrUnknown      = errors.New("unknown token")
	ErrNotActive    = errors.New("token not active")
	ErrDomain       = errors.New("token used outside its requestor")
	ErrCryptogram   = errors.New("cryptogram invalid")
	ErrReplay       = errors.New("cryptogram already used")
	ErrNoCryptogram = errors.New("cryptogram missing")
)

type Token struct {
	Number    string `json:"token"`
	PAN       string `json:"-"`
	Requestor string `json:"requestor"`
	Status    string `json:"status"`
	key       []byte
	lastATC   uint32
}

type Vault struct {
	mu     sync.Mutex
	tokens map[string]*Token
}

func New() *Vault { return &Vault{tokens: map[string]*Token{}} }

// IsToken reports whether a number is in the token range.
func IsToken(n string) bool { return strings.HasPrefix(n, TokenBIN) }

// Provision issues a new token for a card number, bound to one requestor.
func (v *Vault) Provision(pan, requestor string) (*Token, error) {
	if len(pan) < 13 || requestor == "" || IsToken(pan) {
		return nil, errors.New("a card number and a requestor are required")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for {
		n := luhnComplete(TokenBIN + randomDigits(len(pan)-len(TokenBIN)-1))
		if _, taken := v.tokens[n]; !taken {
			t := &Token{Number: n, PAN: pan, Requestor: requestor, Status: "ACTIVE", key: key}
			v.tokens[n] = t
			return t, nil
		}
	}
}

// Cryptogram issues the next single-use cryptogram for a payment by the token's requestor. Wire form (field 48):
// "TAVV:<base64 HMAC>:<counter>".
func (v *Vault) Cryptogram(token, requestor string, amountMinor int64) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.tokens[token]
	switch {
	case !ok:
		return "", ErrUnknown
	case t.Status != "ACTIVE":
		return "", ErrNotActive
	case t.Requestor != requestor:
		return "", ErrDomain
	}
	atc := t.lastATC + 1
	return fmt.Sprintf("TAVV:%s:%d", mac(t, amountMinor, atc), atc), nil
}

// Detokenize checks a token payment (status, requestor, cryptogram, counter) and returns the card number. A counter
// is accepted once and must be newer than the last accepted one.
func (v *Vault) Detokenize(token, requestor string, amountMinor int64, cryptogram string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.tokens[token]
	if !ok {
		return "", ErrUnknown
	}
	if t.Status != "ACTIVE" {
		return "", ErrNotActive
	}
	if t.Requestor != requestor {
		return "", ErrDomain
	}
	parts := strings.Split(cryptogram, ":")
	if len(parts) != 3 || parts[0] != "TAVV" {
		return "", ErrNoCryptogram
	}
	atc64, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return "", ErrCryptogram
	}
	atc := uint32(atc64)
	if !hmac.Equal([]byte(parts[1]), []byte(mac(t, amountMinor, atc))) {
		return "", ErrCryptogram
	}
	if atc <= t.lastATC {
		return "", ErrReplay
	}
	t.lastATC = atc
	return t.PAN, nil
}

// SetStatus moves a token through its lifecycle: ACTIVE <-> SUSPENDED, any -> DELETED (final).
func (v *Vault) SetStatus(token, status string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.tokens[token]
	if !ok {
		return ErrUnknown
	}
	if t.Status == "DELETED" || (status != "ACTIVE" && status != "SUSPENDED" && status != "DELETED") {
		return fmt.Errorf("cannot move a %s token to %s", t.Status, status)
	}
	t.Status = status
	return nil
}

// ReplaceCard re-points a card's live tokens at its replacement (the issuer replaced a lost or stolen card), so
// merchants keep working tokens. Returns how many moved.
func (v *Vault) ReplaceCard(oldPAN, newPAN string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, t := range v.tokens {
		if t.PAN == oldPAN && t.Status != "DELETED" {
			t.PAN = newPAN
			n++
		}
	}
	return n
}

func mac(t *Token, amountMinor int64, atc uint32) string {
	h := hmac.New(sha256.New, t.key)
	fmt.Fprintf(h, "%s|%s|%d|%d", t.Number, t.Requestor, amountMinor, atc)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

func randomDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String()
}

// luhnComplete appends the Luhn check digit.
func luhnComplete(s string) string {
	sum := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if (len(s)-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return s + strconv.Itoa((10-sum%10)%10)
}

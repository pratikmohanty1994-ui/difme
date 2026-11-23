// Package scheme simulates a card network with its issuers for DIFME's dev and verification clusters: it answers
// ISO 8583 authorisations, purchases, reversals and echo tests against a card ledger (limit, outstanding, expiry,
// status), with switchable issuer outages. Test cards only: no real card data belongs here.
package scheme

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moov-io/iso8583"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/tokens"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

// Response codes used (ISO 8583:1987 field 39).
const (
	Approved         = "00"
	DoNotHonour      = "05"
	InvalidAmount    = "13"
	InvalidCard      = "14"
	UnableToLocate   = "25"
	FormatError      = "30"
	InsufficientFund = "51"
	ExpiredCard      = "54"
	Restricted       = "62"
	IssuerDown       = "91"
	Duplicate        = "94"
)

// Card is one test card at its issuer.
type Card struct {
	PAN              string `json:"pan"`
	Expiry           string `json:"expiry"` // YYMM
	LimitMinor       int64  `json:"limitMinor"`
	OutstandingMinor int64  `json:"outstandingMinor"`
	Status           string `json:"status"` // ACTIVE, BLOCKED, RESTRICTED
	Holder           string `json:"holder,omitempty"`
	// 3-D Secure authentication channels the cardholder enrolled (ADR-027): "sms", "email", "app" (DIFME app, out of band)
	Channels []string `json:"channels,omitempty"`
}

// Txn is one processed message, kept for the admin API (PAN masked).
type Txn struct {
	At           time.Time `json:"at"`
	MTI          string    `json:"mti"`
	PAN          string    `json:"pan"`
	AmountMinor  int64     `json:"amountMinor"`
	Currency     string    `json:"currency"`
	MCC          string    `json:"mcc,omitempty"`
	Merchant     string    `json:"merchant,omitempty"`
	STAN         string    `json:"stan"`
	RRN          string    `json:"rrn"`
	AuthCode     string    `json:"authCode,omitempty"`
	ResponseCode string    `json:"responseCode"`
	State        string    `json:"state"`                 // AUTHORISED, DECLINED, REVERSED, REFUNDED (a refund credit)
	OriginalRRN  string    `json:"originalRrn,omitempty"` // refunds: the purchase they credit back
	ECI          string    `json:"eci,omitempty"`         // 3-D Secure: 05 authenticated (CAVV verified), 06 attempt

	pan           string // full PAN, never serialised: reversals and refunds find the card by it, not by the mask
	issuerAuth    string // the issuer host's authorisation id (cards held by card-issuer)
	refundedMinor int64  // purchases: total credited back so far
}

// Network is the simulated scheme plus issuers. Safe for concurrent use.
type Network struct {
	Tokens *tokens.Vault // network tokens (ADR-024): swapped for the card number before the issuer sees them
	// Issuer is the issuer host for cards the network does not hold itself (card-issuer, ADR-024): it decides,
	// holds the funds and clears; nil means only the simulator's own test cards exist.
	Issuer Issuer
	// HSM verifies 3-D Secure CAVVs (ADR-027); nil means CAVV payments cannot be verified and are declined (91).
	HSM   threeds.HSM
	atns  map[string]bool // PAN|ATN of accepted CAVVs: each authentication pays once
	mu    sync.Mutex
	cards map[string]*Card
	down  map[string]bool // BIN (first 6) -> issuer unavailable
	byRRN map[string]*Txn // approved authorisations by RRN (for reversals)
	seen  map[string]*Txn // terminal|STAN -> answer, for retransmissions
	log   []*Txn
	now   func() time.Time
	keep  int
}

func New() *Network {
	return &Network{Tokens: tokens.New(), atns: map[string]bool{}, cards: map[string]*Card{}, down: map[string]bool{}, byRRN: map[string]*Txn{}, seen: map[string]*Txn{},
		now: time.Now, keep: 10_000}
}

// PutCard adds or replaces a test card.
func (n *Network) PutCard(c Card) error {
	if len(c.PAN) < 12 || len(c.PAN) > 19 || strings.Trim(c.PAN, "0123456789") != "" {
		return errors.New("pan must be 12-19 digits")
	}
	if len(c.Expiry) != 4 || strings.Trim(c.Expiry, "0123456789") != "" {
		return errors.New("expiry must be YYMM")
	}
	if c.LimitMinor < 0 || c.OutstandingMinor < 0 {
		return errors.New("limit and outstanding can't be negative")
	}
	switch c.Status {
	case "":
		c.Status = "ACTIVE"
	case "ACTIVE", "BLOCKED", "RESTRICTED":
	default:
		return errors.New("status must be ACTIVE, BLOCKED or RESTRICTED")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	cc := c
	n.cards[c.PAN] = &cc
	return nil
}

// Card returns a copy of a card.
func (n *Network) Card(pan string) (Card, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.cards[pan]
	if !ok {
		return Card{}, false
	}
	return *c, true
}

// SetIssuerDown switches an issuer (by BIN) off or on: its cards then get 91.
func (n *Network) SetIssuerDown(bin string, down bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.down[bin] = down
}

// Transactions returns the newest processed messages first.
func (n *Network) Transactions(limit int) []Txn {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []Txn{}
	for i := len(n.log) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, *n.log[i])
	}
	return out
}

// Mask keeps the BIN and last four digits.
func Mask(pan string) string {
	if len(pan) < 10 {
		return "****"
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

// Handle answers one request message (0100, 0200, 0400, 0800) with its response.
func (n *Network) Handle(req *iso8583.Message) (*iso8583.Message, error) {
	mti, err := req.GetMTI()
	if err != nil {
		return nil, err
	}
	resp := iso8583.NewMessage(wire.Spec)
	for _, f := range []int{2, 3, 4, 7, 11, 12, 13, 18, 22, 37, 41, 42, 49} { // echo the identifying fields
		if v := wire.Get(req, f); v != "" {
			_ = resp.Field(f, v)
		}
	}
	switch mti {
	case "0800":
		resp.MTI("0810")
		_ = resp.Field(39, Approved)
		return resp, nil
	case "0100", "0200":
		if mti == "0100" {
			resp.MTI("0110")
		} else {
			resp.MTI("0210")
		}
		var t *Txn
		if strings.HasPrefix(wire.Get(req, 3), "20") { // processing code 20xxxx: refund (credit to the card)
			t = n.refund(req, mti)
		} else {
			t = n.authorise(req, mti)
		}
		if t.RRN != "" {
			_ = resp.Field(37, t.RRN)
		}
		if t.AuthCode != "" {
			_ = resp.Field(38, t.AuthCode)
		}
		_ = resp.Field(39, t.ResponseCode)
		return resp, nil
	case "0400", "0420":
		resp.MTI(map[string]string{"0400": "0410", "0420": "0430"}[mti])
		_ = resp.Field(39, n.reverse(req))
		return resp, nil
	default:
		return nil, fmt.Errorf("unsupported MTI %s", mti)
	}
}

func (n *Network) authorise(req *iso8583.Message, mti string) *Txn {
	pan, stan, term := wire.Get(req, 2), wire.Get(req, 11), wire.Get(req, 41)
	amount, aerr := strconv.ParseInt(strings.TrimLeft(wire.Get(req, 4), "0")+"0", 10, 64)
	amount /= 10 // the appended 0 keeps "" and "000…" parseable
	// 3-D Secure: field 48 "CAVV:<authenticationValue>" on a card number. The security module is called before the
	// lock (a network call); replay is checked under it.
	var cavv *threeds.CAVV
	var cavvErr error
	if f48 := wire.Get(req, 48); strings.HasPrefix(f48, "CAVV:") && !tokens.IsToken(pan) {
		if n.HSM == nil {
			cavvErr = errNoHSM
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c, err := threeds.Verify(ctx, n.HSM, pan, strings.TrimPrefix(f48, "CAVV:"))
			cancel()
			cavv, cavvErr = &c, err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	key := term + "|" + stan
	if prev, ok := n.seen[key]; ok && prev.PAN == Mask(pan) && prev.AmountMinor == amount {
		return prev // retransmission: same answer, no second hold
	}
	t := &Txn{At: n.now(), MTI: mti, PAN: Mask(pan), AmountMinor: amount, Currency: wire.Get(req, 49), MCC: wire.Get(req, 18),
		Merchant: wire.Get(req, 42), STAN: stan, State: "DECLINED"}
	t.pan = pan
	// A network token: check it (status, requestor = merchant field 42, cryptogram in field 48) and swap in the card
	// number; the response keeps the token (field 2 is echoed from the request).
	var tokenErr error
	if tokens.IsToken(pan) {
		var real string
		real, tokenErr = n.Tokens.Detokenize(pan, wire.Get(req, 42), amount, wire.Get(req, 48))
		if tokenErr == nil {
			pan = real
		}
	}
	c, ok := n.cards[pan]
	if !ok && n.Issuer != nil && tokenErr == nil && cavvErr == nil && stan != "" && pan != "" && aerr == nil && amount > 0 &&
		!(cavv != nil && n.atns[pan+"|"+strconv.FormatUint(uint64(cavv.ATN), 10)]) {
		return n.viaIssuer(t, key, req, mti, pan, amount, cavv)
	}
	switch {
	case stan == "" || pan == "" || aerr != nil:
		t.ResponseCode = FormatError
	case errors.Is(tokenErr, tokens.ErrUnknown):
		t.ResponseCode = InvalidCard
	case errors.Is(tokenErr, tokens.ErrNotActive), errors.Is(tokenErr, tokens.ErrDomain):
		t.ResponseCode = Restricted
	case tokenErr != nil: // cryptogram missing, invalid or replayed
		t.ResponseCode = DoNotHonour
	case errors.Is(cavvErr, errNoHSM):
		t.ResponseCode = IssuerDown
	case cavvErr != nil && !errors.Is(cavvErr, threeds.ErrFormat) && !errors.Is(cavvErr, threeds.ErrCryptogram):
		t.ResponseCode = IssuerDown // security module unreachable
	case cavvErr != nil: // malformed or forged CAVV
		t.ResponseCode = DoNotHonour
	case cavv != nil && n.atns[pan+"|"+strconv.FormatUint(uint64(cavv.ATN), 10)]:
		t.ResponseCode = DoNotHonour // CAVV replayed: the authentication was already used
	case amount <= 0:
		t.ResponseCode = InvalidAmount
	case !ok:
		t.ResponseCode = InvalidCard
	case n.down[pan[:6]]:
		t.ResponseCode = IssuerDown
	case c.Status == "BLOCKED":
		t.ResponseCode = DoNotHonour
	case c.Status == "RESTRICTED":
		t.ResponseCode = Restricted
	case c.Expiry < n.now().Format("0601"):
		t.ResponseCode = ExpiredCard
	case wire.Get(req, 14) != "" && wire.Get(req, 14) != c.Expiry:
		t.ResponseCode = ExpiredCard // expiry presented doesn't match the card
	case c.LimitMinor-c.OutstandingMinor < amount:
		t.ResponseCode = InsufficientFund
	default:
		c.OutstandingMinor += amount
		t.ResponseCode, t.State, t.AuthCode = Approved, "AUTHORISED", digits(6)
		if cavv != nil {
			n.atns[pan+"|"+strconv.FormatUint(uint64(cavv.ATN), 10)] = true
			t.ECI = fmt.Sprintf("%02d", cavv.ECI)
		}
	}
	t.RRN = digits(12)
	if t.State == "AUTHORISED" {
		n.byRRN[t.RRN] = t
	}
	n.seen[key] = t
	n.record(t)
	return t
}

var errNoHSM = errors.New("no security module for CAVV")

// viaIssuer asks the issuer host for the decision (caller holds n.mu). 0200 purchases are cleared at once.
func (n *Network) viaIssuer(t *Txn, key string, req *iso8583.Message, mti, pan string, amount int64, cavv *threeds.CAVV) *Txn {
	ir := IssuerRequest{PAN: pan, Expiry: wire.Get(req, 14), AmountMinor: amount, Currency: wire.Get(req, 49), Merchant: wire.Get(req, 42)}
	if f48 := wire.Get(req, 48); strings.HasPrefix(f48, "CVV2:") {
		ir.CVV2 = strings.TrimPrefix(f48, "CVV2:")
	}
	if pb := wire.Get(req, 52); pb != "" {
		ir.PINBlock = strings.ToUpper(hex.EncodeToString([]byte(pb)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, id, err := n.Issuer.Authorise(ctx, ir)
	switch {
	case err != nil:
		t.ResponseCode = IssuerDown
	case code != Approved:
		t.ResponseCode = code
	default:
		t.ResponseCode, t.State, t.AuthCode, t.issuerAuth = Approved, "AUTHORISED", digits(6), id
		if mti == "0200" {
			// Field 55 (card-present chip): card-issuer verifies the TC/ARQC before posting and refuses it otherwise.
			if err := n.Issuer.Clear(ctx, id, amount, wire.Get(req, 55)); err != nil {
				_ = n.Issuer.Reverse(ctx, id)
				code := IssuerDown
				if errors.Is(err, ErrIssuerRefused) {
					code = "05" // refused by the issuer (e.g. chip cryptogram does not verify), not unavailable
				}
				t.ResponseCode, t.State, t.AuthCode = code, "DECLINED", ""
			}
		}
		if t.State == "AUTHORISED" && cavv != nil {
			n.atns[pan+"|"+strconv.FormatUint(uint64(cavv.ATN), 10)] = true
			t.ECI = fmt.Sprintf("%02d", cavv.ECI)
		}
	}
	t.RRN = digits(12)
	if t.State == "AUTHORISED" {
		n.byRRN[t.RRN] = t
	}
	n.seen[key] = t
	n.record(t)
	return t
}

// refund credits part or all of an earlier approved purchase back to its card: field 37 carries the purchase's RRN,
// field 2 must be that purchase's card, and the credits on one purchase never add up to more than it.
func (n *Network) refund(req *iso8583.Message, mti string) *Txn {
	pan, stan, term, orig := wire.Get(req, 2), wire.Get(req, 11), wire.Get(req, 41), wire.Get(req, 37)
	amount, aerr := strconv.ParseInt(strings.TrimLeft(wire.Get(req, 4), "0")+"0", 10, 64)
	amount /= 10
	n.mu.Lock()
	defer n.mu.Unlock()
	key := term + "|" + stan
	if prev, ok := n.seen[key]; ok && prev.PAN == Mask(pan) && prev.AmountMinor == amount {
		return prev // retransmission: same answer, no second credit
	}
	t := &Txn{At: n.now(), MTI: mti, PAN: Mask(pan), AmountMinor: amount, Currency: wire.Get(req, 49), Merchant: wire.Get(req, 42),
		STAN: stan, OriginalRRN: orig, State: "DECLINED", pan: pan}
	p, ok := n.byRRN[orig]
	switch {
	case stan == "" || pan == "" || orig == "" || aerr != nil:
		t.ResponseCode = FormatError
	case !ok || p.pan != pan:
		t.ResponseCode = UnableToLocate
	case p.State != "AUTHORISED":
		t.ResponseCode = DoNotHonour // reversed purchases have nothing left to refund
	case amount <= 0 || p.refundedMinor+amount > p.AmountMinor:
		t.ResponseCode = InvalidAmount
	default:
		p.refundedMinor += amount
		if c, ok := n.cards[pan]; ok {
			c.OutstandingMinor -= amount
			if c.OutstandingMinor < 0 {
				c.OutstandingMinor = 0
			}
		}
		t.ResponseCode, t.State, t.AuthCode = Approved, "REFUNDED", digits(6)
	}
	t.RRN = digits(12)
	n.seen[key] = t
	n.record(t)
	return t
}

func (n *Network) reverse(req *iso8583.Message) string {
	rrn := wire.Get(req, 37)
	n.mu.Lock()
	defer n.mu.Unlock()
	t, ok := n.byRRN[rrn]
	r := &Txn{At: n.now(), MTI: "0400", RRN: rrn, STAN: wire.Get(req, 11), State: "DECLINED"}
	if !ok {
		r.ResponseCode = UnableToLocate
		n.record(r)
		return UnableToLocate
	}
	if t.State == "REVERSED" {
		r.ResponseCode = Approved // already reversed: idempotent
		n.record(r)
		return Approved
	}
	if t.issuerAuth != "" && n.Issuer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := n.Issuer.Reverse(ctx, t.issuerAuth)
		cancel()
		if err != nil {
			r.ResponseCode = IssuerDown
			n.record(r)
			return IssuerDown
		}
	}
	if c, ok := n.cards[t.pan]; ok {
		c.OutstandingMinor -= t.AmountMinor - t.refundedMinor // what a refund already credited isn't released twice
		if c.OutstandingMinor < 0 {
			c.OutstandingMinor = 0
		}
	}
	t.State = "REVERSED"
	r.PAN, r.AmountMinor, r.ResponseCode, r.State = t.PAN, t.AmountMinor, Approved, "REVERSED"
	n.record(r)
	return Approved
}

func (n *Network) record(t *Txn) {
	n.log = append(n.log, t)
	if len(n.log) > n.keep {
		n.log = n.log[len(n.log)-n.keep:]
	}
	if len(n.seen) > 4*n.keep {
		n.seen = map[string]*Txn{}
	}
}

func digits(k int) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint64(b[:])
	s := strconv.FormatUint(v, 10)
	for len(s) < k {
		s = "0" + s
	}
	return s[len(s)-k:]
}

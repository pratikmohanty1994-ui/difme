// Package issuer is DIFME's card issuer (card management, ADR-024/025): it issues debit and credit cards, is the card
// record of truth for the ACS and the authorisation switch, and makes the issuer's authorisation decisions.
//
//   - Debit / prepaid: a Fineract savings account; an authorisation places a hold (holdAmount), clearing releases it and
//     withdraws, a reversal releases it.
//   - Credit: a Fineract multi-disbursement loan as a revolving line (ADR-025 gate): the limit is enforced here as
//     open-to-buy = limit − Fineract principal outstanding − open authorisations (Fineract's own maximum outstanding
//     balance is not revolving); clearing books a disbursement, repayments in Fineract restore the open-to-buy.
//   - Card security (ADR-026): CVV2 and dCVV2 from the security module; PINs only as encrypted blocks (ISO 9564
//     format 4 from the app, translated in the security module); no clear card secrets stored here.
package issuer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"
)

// Products.
const (
	Debit  = "DEBIT"
	Credit = "CREDIT"
)

// Card is the card record (no CVV2, no PIN: those exist only in the security module).
type Card struct {
	ID         string    `json:"id"`
	PAN        string    `json:"-"`
	MaskedPAN  string    `json:"maskedPan"`
	Expiry     string    `json:"expiry"` // YYMM
	Product    string    `json:"product"`
	Account    int64     `json:"account"`              // Fineract savings account (debit) or loan (credit)
	LimitMinor int64     `json:"limitMinor,omitempty"` // credit line
	Status     string    `json:"status"`               // ACTIVE, BLOCKED, RESTRICTED
	Holder     string    `json:"holder"`
	Channels   []string  `json:"channels,omitempty"` // 3-D Secure channels: sms, email, app
	PVV        string    `json:"-"`                  // PIN verification value (from the security module), when a PIN is set
	CreatedAt  time.Time `json:"createdAt"`
}

// Auth is an open or finished authorisation.
type Auth struct {
	ID          string    `json:"id"`
	CardID      string    `json:"cardId"`
	AmountMinor int64     `json:"amountMinor"`
	Currency    string    `json:"currency"`
	Merchant    string    `json:"merchant"`
	State       string    `json:"state"` // HELD, CLEARED, REVERSED, DECLINED
	Code        string    `json:"responseCode"`
	HoldRef     int64     `json:"holdRef,omitempty"` // Fineract hold transaction (debit)
	At          time.Time `json:"at"`
}

// Ledger is the core banking system (Fineract).
type Ledger interface {
	// Debit cards (savings accounts)
	Available(ctx context.Context, savings int64) (int64, error) // minor units, holds already deducted
	Hold(ctx context.Context, savings int64, amountMinor int64, reason string) (int64, error)
	Release(ctx context.Context, savings, holdRef int64) error
	Withdraw(ctx context.Context, savings int64, amountMinor int64, note string) error
	// Credit cards (multi-disbursement loan)
	Outstanding(ctx context.Context, loan int64) (int64, error)
	Disburse(ctx context.Context, loan int64, amountMinor int64) error
}

// HSM is the security module's card functions used here.
type HSM interface {
	CVV2(ctx context.Context, pan, expiry string) (string, error)
	VerifyCVV2(ctx context.Context, pan, expiry, cvv2 string) (bool, error)
	DCVV2(ctx context.Context, pan string) (string, error)
	VerifyDCVV2(ctx context.Context, pan, code string) (bool, error)
	// PINFromApp translates an ISO 9564 format 4 block (app, AES key) to format 0 under the issuer's ZPK.
	PINFromApp(ctx context.Context, pan, iso4Hex string) (string, error)
	PVV(ctx context.Context, pan, pinBlockZPK string) (string, error)
	VerifyPVV(ctx context.Context, pan, pinBlockZPK, pvv string) (bool, error)
}

// Response codes (ISO 8583 field 39).
const (
	Approved     = "00"
	DoNotHonour  = "05"
	InvalidCard  = "14"
	Insufficient = "51"
	Expired      = "54"
	Restricted   = "62"
	WrongPIN     = "55"
	SystemError  = "96"
)

var ErrNotFound = errors.New("not found")

// Issuer holds cards and authorisations (in memory; Store persistence is the deployment's, see store.go).
type Issuer struct {
	BIN    string
	ledger Ledger
	hsm    HSM
	store  Store
	now    func() time.Time
	mu     sync.Mutex
}

func New(bin string, l Ledger, h HSM, s Store) *Issuer {
	return &Issuer{BIN: bin, ledger: l, hsm: h, store: s, now: time.Now}
}

// IssueRequest opens a card on an existing Fineract account.
type IssueRequest struct {
	Product    string   `json:"product"`
	Account    int64    `json:"account"`
	LimitMinor int64    `json:"limitMinor"`
	Holder     string   `json:"holder"`
	Channels   []string `json:"channels"`
}

// Issued is returned once at issuance: the full PAN and CVV2 go to the card bureau / the app's secure display, never
// stored here.
type Issued struct {
	Card
	PANFull string `json:"pan"`
	CVV2    string `json:"cvv2"`
}

func (i *Issuer) Issue(ctx context.Context, r IssueRequest) (Issued, error) {
	if (r.Product != Debit && r.Product != Credit) || r.Account <= 0 || r.Holder == "" || (r.Product == Credit && r.LimitMinor <= 0) {
		return Issued{}, fmt.Errorf("%w: product DEBIT|CREDIT, account, holder and (credit) limitMinor required", ErrInvalid)
	}
	i.mu.Lock()
	var pan string
	for {
		pan = luhn(i.BIN + randomDigits(15-len(i.BIN)))
		if _, err := i.store.CardByPAN(ctx, pan); errors.Is(err, ErrNotFound) {
			break
		}
	}
	i.mu.Unlock()
	expiry := i.now().AddDate(5, 0, 0).Format("0601")
	cvv2, err := i.hsm.CVV2(ctx, pan, expiry)
	if err != nil {
		return Issued{}, fmt.Errorf("security module: %w", err)
	}
	c := Card{ID: "card-" + randomDigits(12), PAN: pan, MaskedPAN: Mask(pan), Expiry: expiry, Product: r.Product, Account: r.Account,
		LimitMinor: r.LimitMinor, Status: "ACTIVE", Holder: r.Holder, Channels: r.Channels, CreatedAt: i.now()}
	if err := i.store.PutCard(ctx, c); err != nil {
		return Issued{}, err
	}
	return Issued{Card: c, PANFull: pan, CVV2: cvv2}, nil
}

var ErrInvalid = errors.New("invalid request")

// SetStatus blocks, restricts or reactivates a card.
func (i *Issuer) SetStatus(ctx context.Context, id, status string) (Card, error) {
	if status != "ACTIVE" && status != "BLOCKED" && status != "RESTRICTED" {
		return Card{}, fmt.Errorf("%w: status ACTIVE|BLOCKED|RESTRICTED", ErrInvalid)
	}
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return Card{}, err
	}
	c.Status = status
	return c, i.store.PutCard(ctx, c)
}

// SetPIN stores the PVV of a PIN chosen in the app (ISO 9564 format 4 block under the app's AES PIN key).
func (i *Issuer) SetPIN(ctx context.Context, id, iso4Hex string) error {
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return err
	}
	block, err := i.hsm.PINFromApp(ctx, c.PAN, iso4Hex)
	if err != nil {
		return fmt.Errorf("%w: PIN block not accepted", ErrInvalid)
	}
	pvv, err := i.hsm.PVV(ctx, c.PAN, block)
	if err != nil {
		return err
	}
	c.PVV = pvv
	return i.store.PutCard(ctx, c)
}

// DynamicCVV2 returns the card's current dCVV2 for the app's display.
func (i *Issuer) DynamicCVV2(ctx context.Context, id string) (string, error) {
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return "", err
	}
	return i.hsm.DCVV2(ctx, c.PAN)
}

// AuthRequest is the switch's authorisation request to the issuer.
type AuthRequest struct {
	PAN         string `json:"pan"`
	Expiry      string `json:"expiry,omitempty"`
	AmountMinor int64  `json:"amountMinor"`
	Currency    string `json:"currency"`
	Merchant    string `json:"merchant"`
	CVV2        string `json:"cvv2,omitempty"`     // static or dynamic (dCVV2)
	PINBlock    string `json:"pinBlock,omitempty"` // ISO 9564 format 0 under the issuer ZPK (already translated by the network)
}

// Authorise decides and, when approved, reserves the funds (debit hold / credit open-to-buy).
func (i *Issuer) Authorise(ctx context.Context, r AuthRequest) (Auth, error) {
	a := Auth{ID: "auth-" + randomDigits(12), AmountMinor: r.AmountMinor, Currency: r.Currency, Merchant: r.Merchant, State: "DECLINED", At: i.now()}
	decline := func(code string) (Auth, error) { a.Code = code; return a, i.store.PutAuth(ctx, a) }
	c, err := i.store.CardByPAN(ctx, r.PAN)
	if errors.Is(err, ErrNotFound) {
		a.Code = InvalidCard
		return a, nil
	} else if err != nil {
		return a, err
	}
	a.CardID = c.ID
	switch {
	case r.AmountMinor <= 0:
		return decline("13")
	case c.Status == "BLOCKED":
		return decline(DoNotHonour)
	case c.Status == "RESTRICTED":
		return decline(Restricted)
	case c.Expiry < i.now().Format("0601") || (r.Expiry != "" && r.Expiry != c.Expiry):
		return decline(Expired)
	}
	if r.CVV2 != "" {
		ok, err := i.hsm.VerifyCVV2(ctx, c.PAN, c.Expiry, r.CVV2)
		if err == nil && !ok {
			ok, err = i.hsm.VerifyDCVV2(ctx, c.PAN, r.CVV2)
		}
		if err != nil {
			return decline(SystemError)
		}
		if !ok {
			return decline(DoNotHonour)
		}
	}
	if r.PINBlock != "" {
		if c.PVV == "" {
			return decline(WrongPIN)
		}
		ok, err := i.hsm.VerifyPVV(ctx, c.PAN, r.PINBlock, c.PVV)
		if err != nil {
			return decline(SystemError)
		}
		if !ok {
			return decline(WrongPIN)
		}
	}
	i.mu.Lock() // one decision at a time per issuer: open-to-buy must not be spent twice
	defer i.mu.Unlock()
	switch c.Product {
	case Debit:
		avail, err := i.ledger.Available(ctx, c.Account)
		if err != nil {
			return decline(SystemError)
		}
		if avail < r.AmountMinor {
			return decline(Insufficient)
		}
		ref, err := i.ledger.Hold(ctx, c.Account, r.AmountMinor, "card auth "+a.ID)
		if err != nil {
			return decline(SystemError)
		}
		a.HoldRef = ref
	case Credit:
		otb, err := i.openToBuy(ctx, c)
		if err != nil {
			return decline(SystemError)
		}
		if otb < r.AmountMinor {
			return decline(Insufficient)
		}
	}
	a.State, a.Code = "HELD", Approved
	return a, i.store.PutAuth(ctx, a)
}

// OpenToBuy for a credit card: limit − principal outstanding in Fineract − open authorisations.
func (i *Issuer) openToBuy(ctx context.Context, c Card) (int64, error) {
	out, err := i.ledger.Outstanding(ctx, c.Account)
	if err != nil {
		return 0, err
	}
	held, err := i.store.HeldTotal(ctx, c.ID)
	if err != nil {
		return 0, err
	}
	return c.LimitMinor - out - held, nil
}

// OpenToBuy is the public form (card id).
func (i *Issuer) OpenToBuy(ctx context.Context, id string) (int64, error) {
	c, err := i.store.Card(ctx, id)
	if err != nil {
		return 0, err
	}
	if c.Product != Credit {
		return i.ledger.Available(ctx, c.Account)
	}
	return i.openToBuy(ctx, c)
}

// Clear posts a held authorisation to the ledger (presentment / capture), for its amount or less.
func (i *Issuer) Clear(ctx context.Context, authID string, amountMinor int64) (Auth, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	a, err := i.store.Auth(ctx, authID)
	if err != nil {
		return Auth{}, err
	}
	if a.State != "HELD" || amountMinor <= 0 || amountMinor > a.AmountMinor {
		return a, fmt.Errorf("%w: only a held authorisation, for at most its amount", ErrInvalid)
	}
	c, err := i.store.Card(ctx, a.CardID)
	if err != nil {
		return a, err
	}
	switch c.Product {
	case Debit:
		if err := i.ledger.Release(ctx, c.Account, a.HoldRef); err != nil {
			return a, err
		}
		if err := i.ledger.Withdraw(ctx, c.Account, amountMinor, "card "+c.MaskedPAN+" "+a.Merchant); err != nil {
			return a, err
		}
	case Credit:
		if err := i.ledger.Disburse(ctx, c.Account, amountMinor); err != nil {
			return a, err
		}
	}
	a.State, a.AmountMinor = "CLEARED", amountMinor
	return a, i.store.PutAuth(ctx, a)
}

// Reverse cancels a held authorisation.
func (i *Issuer) Reverse(ctx context.Context, authID string) (Auth, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	a, err := i.store.Auth(ctx, authID)
	if err != nil {
		return Auth{}, err
	}
	if a.State != "HELD" {
		return a, fmt.Errorf("%w: not a held authorisation", ErrInvalid)
	}
	c, err := i.store.Card(ctx, a.CardID)
	if err != nil {
		return a, err
	}
	if c.Product == Debit {
		if err := i.ledger.Release(ctx, c.Account, a.HoldRef); err != nil {
			return a, err
		}
	}
	a.State = "REVERSED"
	return a, i.store.PutAuth(ctx, a)
}

// CardByPAN serves the ACS (card management lookup).
func (i *Issuer) CardByPAN(ctx context.Context, pan string) (Card, error) {
	return i.store.CardByPAN(ctx, pan)
}

func (i *Issuer) Card(ctx context.Context, id string) (Card, error) { return i.store.Card(ctx, id) }

// Mask keeps the first 6 and last 4 digits.
func Mask(pan string) string {
	if len(pan) < 10 {
		return "****"
	}
	return pan[:6] + "******" + pan[len(pan)-4:]
}

func randomDigits(n int) string {
	out := make([]byte, n)
	for k := range out {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		out[k] = byte('0' + d.Int64())
	}
	return string(out)
}

func luhn(s string) string {
	sum := 0
	for k := len(s) - 1; k >= 0; k-- {
		d := int(s[k] - '0')
		if (len(s)-k)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return s + strconv.Itoa((10-sum%10)%10)
}

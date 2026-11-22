// Package acs is DIFME's lightweight 3-D Secure Access Control Server (ADR-027): the issuer's side of EMV 3DS 2.2.
// The directory server sends an AReq; the ACS looks the card up in card management, asks FRM (Tazama) for a risk
// verdict and answers frictionless (Y, with a CAVV from the security module), challenge (C), reject (R) or not
// authenticated (N). A challenge is a one-time passcode sent to the cardholder (CReq/CRes); its outcome goes to the
// directory server as an RReq. The authorisation switch verifies the CAVV at authorisation (scheme package).
//
// Scope (lightweight): payment authentications (messageCategory 01), browser and app channels with the challenge
// exchanged as JSON CReq/CRes (no HTML challenge page or app-channel JWE yet), OTP as the only challenge method.
package acs

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

// Card is what the ACS needs from card management.
type Card struct {
	Expiry string // YYMM
	Status string // ACTIVE, BLOCKED, RESTRICTED
	Holder string
}

// Cards is card management (CMS).
type Cards interface {
	Card(ctx context.Context, pan string) (Card, bool, error)
}

// OTPSender delivers the passcode to the cardholder (SMS/app push in production).
type OTPSender interface {
	Send(ctx context.Context, pan string, card Card, otp string) error
}

// Results sends the RReq to the directory server.
type Results interface {
	Send(ctx context.Context, rreq RReq) error
}

// AReq is the subset of the EMV 3DS 2.2 authentication request the ACS uses.
type AReq struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	MessageCategory      string `json:"messageCategory"`
	DeviceChannel        string `json:"deviceChannel"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	DSTransID            string `json:"dsTransID"`
	AcctNumber           string `json:"acctNumber"`
	CardExpiryDate       string `json:"cardExpiryDate"`
	PurchaseAmount       string `json:"purchaseAmount"`   // minor units
	PurchaseCurrency     string `json:"purchaseCurrency"` // ISO 4217 numeric
	MerchantName         string `json:"merchantName"`
	AcquirerMerchantID   string `json:"acquirerMerchantID"`
	ChallengeIndicator   string `json:"threeDSRequestorChallengeInd,omitempty"` // 04: challenge mandated
}

type ARes struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	DSTransID            string `json:"dsTransID"`
	ACSTransID           string `json:"acsTransID"`
	TransStatus          string `json:"transStatus"`
	TransStatusReason    string `json:"transStatusReason,omitempty"`
	AuthenticationValue  string `json:"authenticationValue,omitempty"`
	ECI                  string `json:"eci,omitempty"`
	ACSChallengeMandated string `json:"acsChallengeMandated,omitempty"`
	AuthenticationType   string `json:"authenticationType,omitempty"`
	ACSURL               string `json:"acsURL,omitempty"`
}

type CReq struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	ACSTransID           string `json:"acsTransID"`
	ChallengeDataEntry   string `json:"challengeDataEntry,omitempty"`
	ChallengeCancel      string `json:"challengeCancel,omitempty"`
}

type CRes struct {
	MessageType            string `json:"messageType"`
	MessageVersion         string `json:"messageVersion"`
	ThreeDSServerTransID   string `json:"threeDSServerTransID"`
	ACSTransID             string `json:"acsTransID"`
	ChallengeCompletionInd string `json:"challengeCompletionInd"`
	TransStatus            string `json:"transStatus,omitempty"`
	ChallengeInfoText      string `json:"challengeInfoText,omitempty"`
}

type RReq struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	MessageCategory      string `json:"messageCategory"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	DSTransID            string `json:"dsTransID"`
	ACSTransID           string `json:"acsTransID"`
	TransStatus          string `json:"transStatus"`
	TransStatusReason    string `json:"transStatusReason,omitempty"`
	AuthenticationValue  string `json:"authenticationValue,omitempty"`
	ECI                  string `json:"eci,omitempty"`
	InteractionCounter   string `json:"interactionCounter"`
	AuthenticationType   string `json:"authenticationType"`
}

// EMV 3DS transStatusReason codes used here.
const (
	ReasonAuthFailed   = "01"
	ReasonExpiredCard  = "05"
	ReasonInvalidCard  = "06"
	ReasonNoCardRecord = "08"
	ReasonSecurity     = "09"
	ReasonFraud        = "11"
	ReasonNotPermitted = "12"
	ReasonTimedOut     = "14"
	ReasonMaxChallenge = "19"
)

// Config holds the ACS's policy.
type Config struct {
	FrictionlessLimitMinor int64         // above this, always challenge
	OTPTTL                 time.Duration // passcode lifetime
	MaxAttempts            int           // wrong passcodes before N
	ChallengeURL           string        // where the 3DS Server sends CReqs
	PayerKey               []byte        // HMAC key for the opaque card reference sent to FRM
	Now                    func() time.Time
}

type ACS struct {
	cfg     Config
	cards   Cards
	frm     FRM
	hsm     threeds.HSM
	otp     OTPSender
	results Results
	mu      sync.Mutex
	pending map[string]*challenge
}

type challenge struct {
	areq     AReq
	acsID    string
	otpMAC   []byte
	expires  time.Time
	attempts int
	done     bool
}

func New(cfg Config, cards Cards, frm FRM, hsm threeds.HSM, otp OTPSender, results Results) *ACS {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.OTPTTL == 0 {
		cfg.OTPTTL = 5 * time.Minute
	}
	return &ACS{cfg: cfg, cards: cards, frm: frm, hsm: hsm, otp: otp, results: results, pending: map[string]*challenge{}}
}

var ErrBadRequest = errors.New("bad request")

func (a *ACS) payerRef(pan string) string {
	m := hmac.New(sha256.New, a.cfg.PayerKey)
	m.Write([]byte(pan))
	return "card-" + hex.EncodeToString(m.Sum(nil))[:24]
}

func (a *ACS) otpMAC(acsID, otp string) []byte {
	m := hmac.New(sha256.New, a.cfg.PayerKey)
	m.Write([]byte(acsID + "|" + otp))
	return m.Sum(nil)
}

// Authenticate handles an AReq.
func (a *ACS) Authenticate(ctx context.Context, q AReq) (ARes, error) {
	amount, err := strconv.ParseInt(q.PurchaseAmount, 10, 64)
	if q.MessageType != "AReq" || q.ThreeDSServerTransID == "" || len(q.AcctNumber) < 12 || err != nil || amount < 0 {
		return ARes{}, fmt.Errorf("%w: AReq needs messageType, threeDSServerTransID, acctNumber and purchaseAmount", ErrBadRequest)
	}
	res := ARes{MessageType: "ARes", MessageVersion: q.MessageVersion, ThreeDSServerTransID: q.ThreeDSServerTransID, DSTransID: q.DSTransID, ACSTransID: newID()}
	no := func(status, reason string) (ARes, error) {
		res.TransStatus, res.TransStatusReason = status, reason
		slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "status", status, "reason", reason)
		return res, nil
	}
	// card management
	c, found, err := a.cards.Card(ctx, q.AcctNumber)
	switch {
	case err != nil:
		return no("U", ReasonSecurity) // ACS cannot authenticate now; the requestor may proceed without (liability stays)
	case !found:
		return no("N", ReasonNoCardRecord)
	case c.Status == "BLOCKED" || c.Status == "RESTRICTED":
		return no("N", ReasonNotPermitted)
	case c.Expiry < a.cfg.Now().Format("0601") || (q.CardExpiryDate != "" && q.CardExpiryDate != c.Expiry):
		return no("N", ReasonExpiredCard)
	}
	// fraud and risk
	verdict, detail := a.frm.Evaluate(ctx, "3ds-"+res.ACSTransID, a.payerRef(q.AcctNumber), q.AcquirerMerchantID, amount, currencyAlpha(q.PurchaseCurrency))
	slog.Info("3ds risk", "acsTransID", res.ACSTransID, "verdict", verdict, "detail", detail)
	if verdict == Interdict {
		return no("R", ReasonFraud)
	}
	if verdict == NoAlert && amount <= a.cfg.FrictionlessLimitMinor && q.ChallengeIndicator != "04" {
		v, _, err := threeds.Build(ctx, a.hsm, q.AcctNumber, threeds.ResultFriction, 0)
		if err != nil {
			slog.Error("3ds: security module", "err", err)
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationValue, res.ECI = "Y", v, "05"
		slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "status", "Y", "flow", "frictionless")
		return res, nil
	}
	// challenge: one-time passcode
	otp := randomDigits(6)
	ch := &challenge{areq: q, acsID: res.ACSTransID, otpMAC: a.otpMAC(res.ACSTransID, otp), expires: a.cfg.Now().Add(a.cfg.OTPTTL)}
	if err := a.otp.Send(ctx, q.AcctNumber, c, otp); err != nil {
		return no("U", ReasonSecurity)
	}
	a.mu.Lock()
	a.pending[res.ACSTransID] = ch
	a.mu.Unlock()
	res.TransStatus, res.ACSChallengeMandated, res.AuthenticationType, res.ACSURL = "C", "Y", "02", a.cfg.ChallengeURL
	slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "status", "C", "verdict", verdict)
	return res, nil
}

// Challenge handles a CReq: checks the passcode; on the final outcome sends the RReq and answers the CRes.
func (a *ACS) Challenge(ctx context.Context, q CReq) (CRes, error) {
	a.mu.Lock()
	ch, ok := a.pending[q.ACSTransID]
	a.mu.Unlock()
	if q.MessageType != "CReq" || !ok || ch.areq.ThreeDSServerTransID != q.ThreeDSServerTransID {
		return CRes{}, fmt.Errorf("%w: unknown challenge", ErrBadRequest)
	}
	res := CRes{MessageType: "CRes", MessageVersion: q.MessageVersion, ThreeDSServerTransID: q.ThreeDSServerTransID, ACSTransID: q.ACSTransID, ChallengeCompletionInd: "Y"}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ch.done {
		return CRes{}, fmt.Errorf("%w: challenge already completed", ErrBadRequest)
	}
	finish := func(status, reason, value string) (CRes, error) {
		ch.done = true
		delete(a.pending, q.ACSTransID)
		res.TransStatus = status
		rr := RReq{MessageType: "RReq", MessageVersion: ch.areq.MessageVersion, MessageCategory: "01", ThreeDSServerTransID: ch.areq.ThreeDSServerTransID,
			DSTransID: ch.areq.DSTransID, ACSTransID: ch.acsID, TransStatus: status, TransStatusReason: reason, AuthenticationValue: value,
			InteractionCounter: fmt.Sprintf("%02d", ch.attempts), AuthenticationType: "02"}
		if value != "" {
			rr.ECI = "05"
		}
		if err := a.results.Send(ctx, rr); err != nil {
			slog.Error("3ds: RReq", "acsTransID", ch.acsID, "err", err)
		}
		slog.Info("3ds challenge", "acsTransID", ch.acsID, "status", status, "reason", reason, "attempts", ch.attempts)
		return res, nil
	}
	switch {
	case q.ChallengeCancel != "":
		return finish("N", ReasonAuthFailed, "")
	case a.cfg.Now().After(ch.expires):
		return finish("N", ReasonTimedOut, "")
	}
	ch.attempts++
	if hmac.Equal(ch.otpMAC, a.otpMAC(ch.acsID, q.ChallengeDataEntry)) {
		v, _, err := threeds.Build(ctx, a.hsm, ch.areq.AcctNumber, threeds.ResultChallenge, 1)
		if err != nil {
			slog.Error("3ds: security module", "err", err)
			return finish("U", ReasonSecurity, "")
		}
		return finish("Y", "", v)
	}
	if ch.attempts >= a.cfg.MaxAttempts {
		return finish("N", ReasonMaxChallenge, "")
	}
	res.ChallengeCompletionInd, res.ChallengeInfoText = "N", fmt.Sprintf("Incorrect code, %d attempt(s) left", a.cfg.MaxAttempts-ch.attempts)
	return res, nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

func randomDigits(n int) string {
	out := make([]byte, n)
	for i := range out {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		out[i] = byte('0' + d.Int64())
	}
	return string(out)
}

func currencyAlpha(numeric string) string {
	switch numeric {
	case "356", "":
		return "INR"
	case "840":
		return "USD"
	case "978":
		return "EUR"
	}
	return numeric
}

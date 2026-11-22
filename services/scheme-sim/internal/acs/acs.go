// Package acs is DIFME's lightweight 3-D Secure Access Control Server (ADR-027), aligned to EMV 3DS 2.3.1 (2.2.0
// accepted): the issuer's side. The directory server sends an AReq; the ACS looks the card up in card management, asks
// FRM (Tazama) for a risk verdict and answers frictionless (Y, CAVV from the security module), challenge (C),
// decoupled (D), reject (R), not authenticated (N) or unable (U). Challenges: one-time passcode (native text / HTML),
// single-select (choose where the passcode goes), out-of-band approval in the DIFME app, and decoupled authentication;
// the outcome goes to the directory server as an RReq. The authorisation switch verifies the CAVV (scheme package).
//
// Channels: 01 app (CReq/CRes JSON; app-channel JWE: see jwe.go when present), 02 browser (HTML challenge, base64url
// CReq/CRes, result posted to the requestor's notificationURL), 03 3RI (requestor-initiated, no cardholder present).
// Message categories: 01 payment, 02 non-payment.
package acs

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

// Card is what the ACS needs from card management.
type Card struct {
	Expiry   string   // YYMM
	Status   string   // ACTIVE, BLOCKED, RESTRICTED
	Holder   string   //
	Channels []string // enrolled authentication channels: sms, email, app
}

// Cards is card management (CMS).
type Cards interface {
	Card(ctx context.Context, pan string) (Card, bool, error)
}

// OTPSender delivers the passcode to the cardholder over a channel (sms, email).
type OTPSender interface {
	Send(ctx context.Context, pan string, card Card, channel, otp string) error
}

// OOBNotifier asks the cardholder's DIFME app to approve the authentication (push; the app answers through
// ACS.OOBResult after biometric/device authentication).
type OOBNotifier interface {
	Notify(ctx context.Context, pan, acsTransID, merchant string, amountMinor int64, currency string) error
}

// Results sends the RReq to the directory server.
type Results interface {
	Send(ctx context.Context, rreq RReq) error
}

// Supported message versions (2.3.1 preferred).
var Versions = []string{"2.3.1", "2.2.0"}

// AReq is the subset of the EMV 3DS 2.3.1 authentication request the ACS uses.
type AReq struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	MessageCategory      string `json:"messageCategory"` // 01 PA, 02 NPA
	DeviceChannel        string `json:"deviceChannel"`   // 01 app, 02 browser, 03 3RI
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	DSTransID            string `json:"dsTransID"`
	SDKTransID           string `json:"sdkTransID,omitempty"`
	AcctNumber           string `json:"acctNumber"`
	CardExpiryDate       string `json:"cardExpiryDate"`
	PurchaseAmount       string `json:"purchaseAmount,omitempty"`   // minor units (PA)
	PurchaseCurrency     string `json:"purchaseCurrency,omitempty"` // ISO 4217 numeric
	MerchantName         string `json:"merchantName"`
	AcquirerMerchantID   string `json:"acquirerMerchantID"`
	ChallengeIndicator   string `json:"threeDSRequestorChallengeInd,omitempty"` // 04 challenge mandated; 05 no challenge (TRA); 06 data share only
	DecReqInd            string `json:"threeDSRequestorDecReqInd,omitempty"`    // Y: requestor accepts decoupled authentication
	DecMaxTime           string `json:"threeDSRequestorDecMaxTime,omitempty"`   // minutes
	NotificationURL      string `json:"notificationURL,omitempty"`              // browser: where the CRes is posted
	ThreeRIInd           string `json:"threeRIInd,omitempty"`                   // 3RI reason
	SDKEphemPubKey       *JWK   `json:"sdkEphemPubKey,omitempty"`               // app channel: SDK ephemeral key (jwe.go)
	SDKReferenceNumber   string `json:"sdkReferenceNumber,omitempty"`           // app channel: ConcatKDF PartyVInfo
}

type ARes struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	DSTransID            string `json:"dsTransID"`
	ACSTransID           string `json:"acsTransID"`
	SDKTransID           string `json:"sdkTransID,omitempty"`
	TransStatus          string `json:"transStatus"`
	TransStatusReason    string `json:"transStatusReason,omitempty"`
	AuthenticationValue  string `json:"authenticationValue,omitempty"`
	ECI                  string `json:"eci,omitempty"`
	ACSChallengeMandated string `json:"acsChallengeMandated,omitempty"`
	AuthenticationType   string `json:"authenticationType,omitempty"`
	ACSURL               string `json:"acsURL,omitempty"`
	ACSDecConInd         string `json:"acsDecConInd,omitempty"` // Y: decoupled authentication will run
	ACSRenderingType     *Rend  `json:"acsRenderingType,omitempty"`
	ACSSignedContent     string `json:"acsSignedContent,omitempty"` // app channel (jwe.go)
	CardholderInfo       string `json:"cardholderInfo,omitempty"`
}

// Rend is acsRenderingType: interface 01 native / 02 HTML; template 01 text, 02 single-select, 03 multi-select,
// 04 OOB, 05 HTML other, 06 HTML OOB, 07 information.
type Rend struct {
	Interface string `json:"acsInterface"`
	Template  string `json:"acsUiTemplate"`
}

type CReq struct {
	MessageType          string `json:"messageType"`
	MessageVersion       string `json:"messageVersion"`
	ThreeDSServerTransID string `json:"threeDSServerTransID"`
	ACSTransID           string `json:"acsTransID"`
	SDKTransID           string `json:"sdkTransID,omitempty"`
	ChallengeDataEntry   string `json:"challengeDataEntry,omitempty"` // text / single-select answer
	ChallengeCancel      string `json:"challengeCancel,omitempty"`
	OOBContinue          string `json:"oobContinue,omitempty"` // Y: cardholder says the app approval is done
	ResendChallenge      string `json:"resendChallenge,omitempty"`
}

type CRes struct {
	MessageType            string   `json:"messageType"`
	MessageVersion         string   `json:"messageVersion"`
	ThreeDSServerTransID   string   `json:"threeDSServerTransID"`
	ACSTransID             string   `json:"acsTransID"`
	SDKTransID             string   `json:"sdkTransID,omitempty"`
	ChallengeCompletionInd string   `json:"challengeCompletionInd"`
	TransStatus            string   `json:"transStatus,omitempty"`
	ACSUIType              string   `json:"acsUiType,omitempty"` // 01 text, 02 single-select, 03 multi-select, 04 OOB, 05 HTML
	ChallengeInfoHeader    string   `json:"challengeInfoHeader,omitempty"`
	ChallengeInfoText      string   `json:"challengeInfoText,omitempty"`
	ChallengeSelectInfo    []Choice `json:"challengeSelectInfo,omitempty"`
	OOBAppLabel            string   `json:"oobAppLabel,omitempty"`
	OOBContinueLabel       string   `json:"oobContinueLabel,omitempty"`
	ResendInformationLabel string   `json:"resendInformationLabel,omitempty"`
}

// Choice is one challengeSelectInfo entry.
type Choice map[string]string

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
	AuthenticationType   string `json:"authenticationType"` // 02 dynamic (OTP), 03 OOB, 04 decoupled
	ChallengeCancel      string `json:"challengeCancel,omitempty"`
}

// EMV 3DS transStatusReason codes used here.
const (
	ReasonAuthFailed   = "01"
	ReasonExpiredCard  = "05"
	ReasonNoCardRecord = "08"
	ReasonSecurity     = "09"
	ReasonFraud        = "11"
	ReasonNotPermitted = "12"
	ReasonNotEnrolled  = "13"
	ReasonTimedOut     = "14"
	ReasonMaxChallenge = "19"
	Reason3RINotSupp   = "21"
	ReasonDecoupledExp = "24" // decoupled authentication: maximum expiry time reached
)

// Authentication types (RReq / ARes).
const (
	AuthOTP       = "02"
	AuthOOB       = "03"
	AuthDecoupled = "04"
)

// Config holds the ACS's policy.
type Config struct {
	FrictionlessLimitMinor int64         // above this, always challenge
	OTPTTL                 time.Duration // passcode lifetime
	MaxAttempts            int           // wrong passcodes before N
	ChallengeURL           string        // acsURL (browser challenge page / app CReq endpoint)
	PayerKey               []byte        // HMAC key for the opaque card reference sent to FRM and for passcode hashing
	Signer                 *Signer       // app channel: signs acsSignedContent (nil: app-channel challenges refused)
	// MAC computes HMAC-SHA-256 inside the security module (card references for FRM, passcode hashes); when nil,
	// PayerKey is used locally (tests only).
	MAC func(ctx context.Context, data []byte) ([]byte, error)
	Now func() time.Time
}

type ACS struct {
	cfg     Config
	cards   Cards
	frm     FRM
	hsm     threeds.HSM
	otp     OTPSender
	oob     OOBNotifier
	results Results
	mu      sync.Mutex
	pending map[string]*challenge
}

// challenge state: step "select" (choose OTP channel), "otp", "oob" or "decoupled".
type challenge struct {
	areq     AReq
	card     Card
	version  string
	acsID    string
	step     string
	otpMAC   []byte
	expires  time.Time
	attempts int
	oob      string      // "", "approved", "declined"
	app      *AppSession // app channel keys
	done     bool
	result   *RReq
}

func New(cfg Config, cards Cards, frm FRM, hsm threeds.HSM, otp OTPSender, oob OOBNotifier, results Results) *ACS {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.OTPTTL == 0 {
		cfg.OTPTTL = 5 * time.Minute
	}
	return &ACS{cfg: cfg, cards: cards, frm: frm, hsm: hsm, otp: otp, oob: oob, results: results, pending: map[string]*challenge{}}
}

var ErrBadRequest = errors.New("bad request")

func (a *ACS) mac(ctx context.Context, data string) ([]byte, error) {
	if a.cfg.MAC != nil {
		return a.cfg.MAC(ctx, []byte(data))
	}
	m := hmac.New(sha256.New, a.cfg.PayerKey)
	m.Write([]byte(data))
	return m.Sum(nil), nil
}

func (a *ACS) payerRef(ctx context.Context, pan string) (string, error) {
	m, err := a.mac(ctx, "payer|"+pan)
	if err != nil {
		return "", err
	}
	return "card-" + hex.EncodeToString(m)[:24], nil
}

// otpMAC is the stored form of a passcode; nil when the security module cannot be reached (no passcode matches).
func (a *ACS) otpMAC(acsID, otp string) []byte {
	m, err := a.mac(context.Background(), "otp|"+acsID+"|"+otp)
	if err != nil {
		slog.Error("3ds: passcode MAC", "err", err)
		return nil
	}
	return m
}

func otpChannels(c Card) []string {
	var out []string
	for _, ch := range c.Channels {
		if ch == "sms" || ch == "email" {
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		out = []string{"sms"} // card management without channel data: the registered mobile number
	}
	return out
}

// Authenticate handles an AReq.
func (a *ACS) Authenticate(ctx context.Context, q AReq) (ARes, error) {
	if q.MessageType != "AReq" || q.ThreeDSServerTransID == "" || len(q.AcctNumber) < 12 {
		return ARes{}, fmt.Errorf("%w: AReq needs messageType, threeDSServerTransID and acctNumber", ErrBadRequest)
	}
	if !slices.Contains(Versions, q.MessageVersion) {
		return ARes{}, fmt.Errorf("%w: messageVersion %q not supported (%v)", ErrBadRequest, q.MessageVersion, Versions)
	}
	if q.MessageCategory == "" {
		q.MessageCategory = "01"
	}
	if q.DeviceChannel == "" {
		q.DeviceChannel = "02"
	}
	var amount int64
	if q.MessageCategory == "01" {
		var err error
		if amount, err = strconv.ParseInt(q.PurchaseAmount, 10, 64); err != nil || amount < 0 {
			return ARes{}, fmt.Errorf("%w: a payment authentication needs purchaseAmount", ErrBadRequest)
		}
	}
	res := ARes{MessageType: "ARes", MessageVersion: q.MessageVersion, ThreeDSServerTransID: q.ThreeDSServerTransID, DSTransID: q.DSTransID,
		ACSTransID: newID(), SDKTransID: q.SDKTransID}
	no := func(status, reason string) (ARes, error) {
		res.TransStatus, res.TransStatusReason = status, reason
		slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "version", q.MessageVersion, "channel", q.DeviceChannel, "status", status, "reason", reason)
		return res, nil
	}
	c, found, err := a.cards.Card(ctx, q.AcctNumber)
	switch {
	case err != nil:
		return no("U", ReasonSecurity)
	case !found:
		return no("N", ReasonNoCardRecord)
	case c.Status == "BLOCKED" || c.Status == "RESTRICTED":
		return no("N", ReasonNotPermitted)
	case c.Expiry < a.cfg.Now().Format("0601") || (q.CardExpiryDate != "" && q.CardExpiryDate != c.Expiry):
		return no("N", ReasonExpiredCard)
	}
	ref, err := a.payerRef(ctx, q.AcctNumber)
	if err != nil {
		slog.Error("3ds: security module", "err", err)
		return no("U", ReasonSecurity)
	}
	verdict, detail := a.frm.Evaluate(ctx, "3ds-"+res.ACSTransID, ref, q.AcquirerMerchantID, amount, currencyAlpha(q.PurchaseCurrency))
	slog.Info("3ds risk", "acsTransID", res.ACSTransID, "verdict", verdict, "detail", detail)
	if verdict == Interdict {
		return no("R", ReasonFraud)
	}
	frictionless := verdict == NoAlert && amount <= a.cfg.FrictionlessLimitMinor && q.ChallengeIndicator != "04"
	// 3RI: no cardholder to challenge. Non-payment (card verification, recurring set-up) only, on a clear risk verdict.
	if q.DeviceChannel == "03" {
		if q.MessageCategory != "02" {
			return no("N", Reason3RINotSupp)
		}
		if verdict != NoAlert {
			return no("N", ReasonAuthFailed)
		}
		frictionless = true
	}
	if frictionless {
		v, _, err := threeds.Build(ctx, a.hsm, q.AcctNumber, threeds.ResultFriction, 0)
		if err != nil {
			slog.Error("3ds: security module", "err", err)
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationValue, res.ECI = "Y", v, "05"
		slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "version", q.MessageVersion, "status", "Y", "flow", "frictionless")
		return res, nil
	}
	ch := &challenge{areq: q, card: c, version: q.MessageVersion, acsID: res.ACSTransID, expires: a.cfg.Now().Add(a.cfg.OTPTTL)}
	hasApp := slices.Contains(c.Channels, "app")
	switch {
	case q.DecReqInd == "Y" && hasApp:
		// decoupled: the cardholder approves in the DIFME app; the ACS sends the RReq when done or at DecMaxTime
		maxMin, _ := strconv.Atoi(q.DecMaxTime)
		if maxMin <= 0 || maxMin > 10080 {
			maxMin = 10
		}
		ch.step, ch.expires = "decoupled", a.cfg.Now().Add(time.Duration(maxMin)*time.Minute)
		if err := a.oob.Notify(ctx, q.AcctNumber, ch.acsID, q.MerchantName, amount, currencyAlpha(q.PurchaseCurrency)); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.ACSDecConInd, res.AuthenticationType = "D", "Y", AuthDecoupled
		res.CardholderInfo = "Approve this purchase in your DIFME app"
	case hasApp:
		ch.step = "oob"
		if err := a.oob.Notify(ctx, q.AcctNumber, ch.acsID, q.MerchantName, amount, currencyAlpha(q.PurchaseCurrency)); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationType = "C", AuthOOB
		res.ACSRenderingType = rendering(q.DeviceChannel, "04")
	case len(otpChannels(c)) > 1:
		ch.step = "select" // single-select: where to send the passcode
		res.TransStatus, res.AuthenticationType = "C", AuthOTP
		res.ACSRenderingType = rendering(q.DeviceChannel, "02")
	default:
		if err := a.sendOTP(ctx, ch, otpChannels(c)[0]); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationType = "C", AuthOTP
		res.ACSRenderingType = rendering(q.DeviceChannel, "01")
	}
	if res.TransStatus == "C" {
		res.ACSChallengeMandated, res.ACSURL = "Y", a.cfg.ChallengeURL
		if q.DeviceChannel == "01" { // app: key agreement with the SDK, CReq/CRes encrypted
			if q.SDKEphemPubKey == nil || a.cfg.Signer == nil {
				return no("U", ReasonSecurity)
			}
			sess, signed, err := NewAppSession(*q.SDKEphemPubKey, q.SDKReferenceNumber, a.cfg.ChallengeURL, a.cfg.Signer)
			if err != nil {
				return ARes{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
			}
			ch.app, res.ACSSignedContent, res.ACSURL = sess, signed, ""
		}
	}
	a.mu.Lock()
	a.pending[ch.acsID] = ch
	a.mu.Unlock()
	slog.Info("3ds authentication", "acsTransID", ch.acsID, "version", q.MessageVersion, "status", res.TransStatus, "step", ch.step, "verdict", verdict)
	return res, nil
}

func rendering(channel, template string) *Rend {
	if channel == "02" {
		if template == "04" {
			template = "06" // HTML OOB
		}
		return &Rend{Interface: "02", Template: template}
	}
	return &Rend{Interface: "01", Template: template}
}

func (a *ACS) sendOTP(ctx context.Context, ch *challenge, channel string) error {
	otp := randomDigits(6)
	ch.otpMAC, ch.step, ch.expires = a.otpMAC(ch.acsID, otp), "otp", a.cfg.Now().Add(a.cfg.OTPTTL)
	if ch.otpMAC == nil {
		return errors.New("security module unavailable for the passcode")
	}
	return a.otp.Send(ctx, ch.areq.AcctNumber, ch.card, channel, otp)
}

// Challenge handles a CReq (app or browser).
func (a *ACS) Challenge(ctx context.Context, q CReq) (CRes, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, ok := a.pending[q.ACSTransID]
	if q.MessageType != "CReq" || !ok || ch.areq.ThreeDSServerTransID != q.ThreeDSServerTransID || ch.step == "decoupled" {
		return CRes{}, fmt.Errorf("%w: unknown challenge", ErrBadRequest)
	}
	if ch.done {
		return CRes{}, fmt.Errorf("%w: challenge already completed", ErrBadRequest)
	}
	res := CRes{MessageType: "CRes", MessageVersion: ch.version, ThreeDSServerTransID: q.ThreeDSServerTransID, ACSTransID: q.ACSTransID,
		SDKTransID: q.SDKTransID, ChallengeCompletionInd: "N"}
	authType := AuthOTP
	if ch.step == "oob" {
		authType = AuthOOB
	}
	finish := func(status, reason string, result, factor int) (CRes, error) {
		rr := a.finishLocked(ctx, ch, status, reason, authType, result, factor)
		if q.ChallengeCancel != "" {
			rr.ChallengeCancel = q.ChallengeCancel
		}
		res.ChallengeCompletionInd, res.TransStatus = "Y", rr.TransStatus
		return res, nil
	}
	switch {
	case q.ChallengeCancel != "":
		return finish("N", ReasonAuthFailed, 0, 0)
	case a.cfg.Now().After(ch.expires):
		return finish("N", ReasonTimedOut, 0, 0)
	}
	switch ch.step {
	case "select":
		chs := otpChannels(ch.card)
		if !slices.Contains(chs, q.ChallengeDataEntry) {
			res.ACSUIType, res.ChallengeInfoHeader, res.ChallengeInfoText = "02", "Verify your purchase", "Where should we send your code?"
			for _, c := range chs {
				res.ChallengeSelectInfo = append(res.ChallengeSelectInfo, Choice{c: map[string]string{"sms": "Text message", "email": "Email"}[c]})
			}
			return res, nil
		}
		if err := a.sendOTP(ctx, ch, q.ChallengeDataEntry); err != nil {
			return finish("U", ReasonSecurity, 0, 0)
		}
		res.ACSUIType, res.ChallengeInfoHeader, res.ChallengeInfoText = "01", "Verify your purchase", "Enter the code we sent you"
		return res, nil
	case "oob":
		switch {
		case ch.oob == "approved":
			return finish("Y", "", threeds.ResultChallenge, 2)
		case ch.oob == "declined":
			return finish("N", ReasonAuthFailed, 0, 0)
		}
		res.ACSUIType, res.ChallengeInfoHeader = "04", "Approve in your DIFME app"
		res.ChallengeInfoText, res.OOBAppLabel, res.OOBContinueLabel = "We sent a request to your DIFME app. Approve it, then continue.", "DIFME", "Continue"
		return res, nil
	}
	// step "otp"
	if q.ResendChallenge == "Y" {
		if err := a.sendOTP(ctx, ch, otpChannels(ch.card)[0]); err != nil {
			return finish("U", ReasonSecurity, 0, 0)
		}
		res.ACSUIType, res.ChallengeInfoText = "01", "We sent you a new code"
		return res, nil
	}
	if q.ChallengeDataEntry == "" {
		res.ACSUIType, res.ChallengeInfoHeader, res.ChallengeInfoText, res.ResendInformationLabel = "01", "Verify your purchase", "Enter the code we sent you", "Send a new code"
		return res, nil
	}
	ch.attempts++
	if got := a.otpMAC(ch.acsID, q.ChallengeDataEntry); got != nil && hmac.Equal(ch.otpMAC, got) {
		return finish("Y", "", threeds.ResultChallenge, 1)
	}
	if ch.attempts >= a.cfg.MaxAttempts {
		return finish("N", ReasonMaxChallenge, 0, 0)
	}
	res.ACSUIType, res.ChallengeInfoText = "01", fmt.Sprintf("Incorrect code, %d attempt(s) left", a.cfg.MaxAttempts-ch.attempts)
	return res, nil
}

// OOBResult records the DIFME app's answer for an out-of-band or decoupled authentication. In production the app
// approves after biometric/device authentication and signs the answer with its device key; this call comes from the
// app backend over the mesh (mTLS, AuthorizationPolicy). Decoupled authentications finish here (RReq sent).
func (a *ACS) OOBResult(ctx context.Context, acsTransID string, approved bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, ok := a.pending[acsTransID]
	if !ok || ch.done || (ch.step != "oob" && ch.step != "decoupled") {
		return fmt.Errorf("%w: no out-of-band authentication pending", ErrBadRequest)
	}
	if a.cfg.Now().After(ch.expires) {
		a.finishLocked(ctx, ch, "N", ReasonDecoupledExp, AuthDecoupled, 0, 0)
		return nil
	}
	if ch.step == "decoupled" {
		if approved {
			a.finishLocked(ctx, ch, "Y", "", AuthDecoupled, threeds.ResultChallenge, 2)
		} else {
			a.finishLocked(ctx, ch, "N", ReasonAuthFailed, AuthDecoupled, 0, 0)
		}
		return nil
	}
	ch.oob = map[bool]string{true: "approved", false: "declined"}[approved]
	return nil
}

// Expire finishes decoupled authentications past their maximum time (call periodically).
func (a *ACS) Expire(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ch := range a.pending {
		if !ch.done && ch.step == "decoupled" && a.cfg.Now().After(ch.expires) {
			a.finishLocked(ctx, ch, "N", ReasonDecoupledExp, AuthDecoupled, 0, 0)
		}
	}
}

// finishLocked ends a challenge: CAVV on success, RReq to the directory server. Caller holds a.mu.
func (a *ACS) finishLocked(ctx context.Context, ch *challenge, status, reason, authType string, result, factor int) RReq {
	ch.done = true
	delete(a.pending, ch.acsID)
	rr := RReq{MessageType: "RReq", MessageVersion: ch.version, MessageCategory: ch.areq.MessageCategory, ThreeDSServerTransID: ch.areq.ThreeDSServerTransID,
		DSTransID: ch.areq.DSTransID, ACSTransID: ch.acsID, TransStatus: status, TransStatusReason: reason,
		InteractionCounter: fmt.Sprintf("%02d", ch.attempts), AuthenticationType: authType}
	if status == "Y" {
		v, _, err := threeds.Build(ctx, a.hsm, ch.areq.AcctNumber, result, factor)
		if err != nil {
			slog.Error("3ds: security module", "err", err)
			rr.TransStatus, rr.TransStatusReason = "U", ReasonSecurity
		} else {
			rr.AuthenticationValue, rr.ECI = v, "05"
		}
	}
	ch.result = &rr
	if err := a.results.Send(ctx, rr); err != nil {
		slog.Error("3ds: RReq", "acsTransID", ch.acsID, "err", err)
	}
	slog.Info("3ds challenge", "acsTransID", ch.acsID, "status", rr.TransStatus, "reason", reason, "type", authType, "attempts", ch.attempts)
	return rr
}

// NotificationURL returns where a browser challenge's CRes goes (the AReq's notificationURL).
func (a *ACS) notificationURL(acsTransID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ch, ok := a.pending[acsTransID]; ok {
		return ch.areq.NotificationURL
	}
	return ""
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

// AppChallenge handles an encrypted CReq (app channel): the JWE header's kid is the acsTransID.
func (a *ACS) AppChallenge(ctx context.Context, jwe string) (string, error) {
	hb, err := b64.DecodeString(strings.SplitN(jwe, ".", 2)[0])
	var hdr struct{ Kid string }
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return "", fmt.Errorf("%w: JWE header", ErrBadRequest)
	}
	a.mu.Lock()
	ch, ok := a.pending[hdr.Kid]
	a.mu.Unlock()
	if !ok || ch.app == nil {
		return "", fmt.Errorf("%w: unknown app challenge", ErrBadRequest)
	}
	pt, enc, err := ch.app.DecryptCReq(jwe)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	var q CReq
	if err := json.Unmarshal(pt, &q); err != nil || q.ACSTransID != hdr.Kid {
		return "", fmt.Errorf("%w: CReq does not match the JWE", ErrBadRequest)
	}
	res, err := a.Challenge(ctx, q)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return ch.app.EncryptCRes(out, enc, hdr.Kid)
}

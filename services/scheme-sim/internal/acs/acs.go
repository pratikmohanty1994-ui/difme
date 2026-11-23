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
	"net/http"
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
	PurchaseExponent     string `json:"purchaseExponent,omitempty"`             // minor-unit exponent (default 2) [EMV-220]
	SPCSupport           string `json:"threeDSRequestorSpcSupport,omitempty"`   // Y: requestor can call SPC (fido.go) [RAVELIN]
	PayeeOrigin          string `json:"payeeOrigin,omitempty"`                  // SPC payee origin [RAVELIN]
	// FIDO data from the requestor: 06/07 FIDO Authentication Data, 09 SPC assertion (AReq #2) (fido.go)
	ReqAuthInfo   *ReqAuthInfo   `json:"threeDSRequestorAuthenticationInfo,omitempty"`
	PriorAuthInfo *PriorAuthInfo `json:"threeDSRequestorPriorAuthenticationInfo,omitempty"`
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
	// 2.3.1 only (fido.go): authenticationMethod (13 WebAuthn, 14 SPC), acsInfoInd (06/07), merchant-initiated SPC data
	AuthenticationMethod []string       `json:"authenticationMethod,omitempty"`
	ACSInfoInd           []string       `json:"acsInfoInd,omitempty"`
	WebAuthnCredList     []WebAuthnCred `json:"webAuthnCredList,omitempty"`
	SPCTransData         *SPCTransData  `json:"spcTransData,omitempty"`
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
	// Browser challenge page form fields (not EMV CReq members): the WebAuthn/SPC assertion (JSON PublicKeyCredential)
	// or Y when the browser declined and the cardholder falls back to a one-time passcode.
	FIDOAssertion string `json:"-"`
	FIDOFallback  string `json:"-"`
}

type CRes struct {
	MessageType            string       `json:"messageType"`
	MessageVersion         string       `json:"messageVersion"`
	ThreeDSServerTransID   string       `json:"threeDSServerTransID"`
	ACSTransID             string       `json:"acsTransID"`
	SDKTransID             string       `json:"sdkTransID,omitempty"`
	ChallengeCompletionInd string       `json:"challengeCompletionInd"`
	TransStatus            string       `json:"transStatus,omitempty"`
	ACSUIType              string       `json:"acsUiType,omitempty"` // 01 text, 02 single-select, 03 multi-select, 04 OOB, 05 HTML
	ChallengeInfoHeader    string       `json:"challengeInfoHeader,omitempty"`
	ChallengeInfoText      string       `json:"challengeInfoText,omitempty"`
	ChallengeSelectInfo    []Choice     `json:"challengeSelectInfo,omitempty"`
	OOBAppLabel            string       `json:"oobAppLabel,omitempty"`
	OOBContinueLabel       string       `json:"oobContinueLabel,omitempty"`
	ResendInformationLabel string       `json:"resendInformationLabel,omitempty"`
	FIDO                   *FIDORequest `json:"-"` // browser page only: WebAuthn/SPC request (acsUiType 05)
}

// Choice is one challengeSelectInfo entry.
type Choice map[string]string

type RReq struct {
	MessageType          string   `json:"messageType"`
	MessageVersion       string   `json:"messageVersion"`
	MessageCategory      string   `json:"messageCategory"`
	ThreeDSServerTransID string   `json:"threeDSServerTransID"`
	DSTransID            string   `json:"dsTransID"`
	ACSTransID           string   `json:"acsTransID"`
	TransStatus          string   `json:"transStatus"`
	TransStatusReason    string   `json:"transStatusReason,omitempty"`
	AuthenticationValue  string   `json:"authenticationValue,omitempty"`
	ECI                  string   `json:"eci,omitempty"`
	InteractionCounter   string   `json:"interactionCounter"`
	AuthenticationType   string   `json:"authenticationType"`             // 02 dynamic (OTP, FIDO assertion), 03 OOB, 04 decoupled
	AuthenticationMethod []string `json:"authenticationMethod,omitempty"` // 2.3.1: 13 WebAuthn, 14 SPC (fido.go)
	ChallengeCancel      string   `json:"challengeCancel,omitempty"`
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
	// Store keeps pending challenges (nil: in memory, lost on restart; PostgresStore survives restarts).
	Store ChallengeStore
	// Instance names this ACS process (e.g. the pod's host name) so that, after a restart, Recover can end the
	// app-channel challenges whose session keys died with the previous process.
	Instance string
	// FIDO turns on WebAuthn / SPC authentication (fido.go); Credentials stores registered credentials (nil: memory).
	FIDO        FIDOConfig
	Credentials CredentialStore
	// IssuerAuth guards the issuer/cardholder endpoints (out-of-band answer, FIDO registration). nil: the mesh alone
	// (mTLS + AuthorizationPolicy) controls who reaches them.
	IssuerAuth func(r *http.Request) bool
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
	store   ChallengeStore
	creds   CredentialStore
	apps    map[string]*AppSession // app-channel session keys by acsTransID: process memory only, never stored
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
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.Credentials == nil {
		cfg.Credentials = NewMemoryCredentials()
	}
	return &ACS{cfg: cfg, cards: cards, frm: frm, hsm: hsm, otp: otp, oob: oob, results: results, store: cfg.Store, creds: cfg.Credentials,
		apps: map[string]*AppSession{}}
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
	// FIDO data from the 3DS Requestor (fido.go): 06/07 FIDO Authentication Data is risk input; 09 is AReq #2 of
	// merchant-initiated SPC, whose assertion decides the outcome (Y with CAVV, N, or an OTP challenge).
	spcFallback := false
	if info := q.ReqAuthInfo; info != nil {
		switch info.Method {
		case ReqAuthFIDO, ReqAuthFIDOSigned:
			trusted, err := a.requestorFIDO(info)
			slog.Info("3ds requestor FIDO data", "acsTransID", res.ACSTransID, "method", info.Method, "trusted", trusted, "err", err)
		case ReqAuthSPCAssertion:
			var m string
			err := errFIDOFallback // FIDO off: challenge as usual
			if a.fidoOn() {
				m, err = a.spcSecondAReq(ctx, q)
			}
			switch {
			case err == nil:
				v, _, err := threeds.Build(ctx, a.hsm, q.AcctNumber, threeds.ResultChallenge, SecondFactorFIDO)
				if err != nil {
					slog.Error("3ds: security module", "err", err)
					return no("U", ReasonSecurity)
				}
				res.TransStatus, res.AuthenticationValue, res.ECI, res.AuthenticationType = "Y", v, "05", AuthOTP
				if q.MessageVersion == "2.3.1" {
					res.AuthenticationMethod = []string{m}
				}
				slog.Info("3ds authentication", "acsTransID", res.ACSTransID, "version", q.MessageVersion, "status", "Y", "flow", "spc", "prior", q.PriorAuthInfo.Ref)
				return res, nil
			case errors.Is(err, errFIDOFallback):
				spcFallback = true // unknown/expired prior SPC transaction or credential: challenge with a passcode
			case errors.Is(err, errFIDOCounter):
				return no("N", ReasonSecurity)
			case errors.Is(err, errFIDOVerify):
				slog.Info("3ds SPC assertion rejected", "acsTransID", res.ACSTransID, "err", err)
				return no("N", ReasonAuthFailed)
			default:
				slog.Error("3ds: SPC", "acsTransID", res.ACSTransID, "err", err)
				return no("U", ReasonSecurity)
			}
		}
	}
	frictionless := verdict == NoAlert && amount <= a.cfg.FrictionlessLimitMinor && q.ChallengeIndicator != "04" && !spcFallback
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
	ch := &ChallengeState{AReq: q, Card: c, Version: q.MessageVersion, ACSTransID: res.ACSTransID, Expires: a.cfg.Now().Add(a.cfg.OTPTTL), CardRef: ref}
	hasApp := slices.Contains(c.Channels, "app")
	// WebAuthn / SPC (fido.go): browser channel, card with registered credentials; else the methods below (OTP).
	var creds []FIDOCredential
	if a.fidoOn() && q.DeviceChannel == "02" && !spcFallback {
		if creds, err = a.creds.Credentials(ctx, ref); err != nil {
			slog.Error("3ds: FIDO credential store", "err", err)
			creds = nil
		}
	}
	anySPC := slices.ContainsFunc(creds, func(c FIDOCredential) bool { return c.SPC }) && q.MessageCategory == "01"
	if len(creds) > 0 && q.MessageVersion == "2.3.1" {
		res.ACSInfoInd = []string{ACSInfoWebAuthn}
		if anySPC {
			res.ACSInfoInd = append(res.ACSInfoInd, ACSInfoSPC)
		}
	}
	switch {
	case q.DecReqInd == "Y" && hasApp:
		// decoupled: the cardholder approves in the DIFME app; the ACS sends the RReq when done or at DecMaxTime
		maxMin, _ := strconv.Atoi(q.DecMaxTime)
		if maxMin <= 0 || maxMin > 10080 {
			maxMin = 10
		}
		ch.Step, ch.Expires = "decoupled", a.cfg.Now().Add(time.Duration(maxMin)*time.Minute)
		if err := a.oob.Notify(ctx, q.AcctNumber, ch.ACSTransID, q.MerchantName, amount, currencyAlpha(q.PurchaseCurrency)); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.ACSDecConInd, res.AuthenticationType = "D", "Y", AuthDecoupled
		res.CardholderInfo = "Approve this purchase in your DIFME app"
	case anySPC && q.SPCSupport == "Y" && q.MessageVersion == "2.3.1":
		// merchant-initiated SPC [EMVCO-SPC]: ARes S with the credential list and SPC transaction data; the requestor
		// calls SPC and sends the assertion in AReq #2 (spcSecondAReq)
		ch.Step, ch.FIDO, ch.Expires = "spc", newFIDOPending(q, creds, true), a.cfg.Now().Add(a.fidoTimeout()+time.Minute)
		res.TransStatus, res.AuthenticationMethod = StatusSPC, []string{MethodSPC}
		res.SPCTransData, res.WebAuthnCredList = a.spcTransData(ch)
	case len(creds) > 0:
		// issuer-initiated: the ACS's HTML challenge page calls SPC (payment) or WebAuthn [EMVCO-SPC]
		ch.Step, ch.FIDO = "fido", newFIDOPending(q, creds, false)
		res.TransStatus, res.AuthenticationType = "C", AuthOTP // authenticationType has no FIDO value: 02 dynamic
		res.ACSRenderingType = &Rend{Interface: "02", Template: "05"}
		if q.MessageVersion == "2.3.1" {
			res.AuthenticationMethod = []string{MethodWebAuthn}
			if ch.FIDO.SPC {
				res.AuthenticationMethod = []string{MethodSPC, MethodWebAuthn}
			}
		}
	case hasApp:
		ch.Step = "oob"
		if err := a.oob.Notify(ctx, q.AcctNumber, ch.ACSTransID, q.MerchantName, amount, currencyAlpha(q.PurchaseCurrency)); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationType = "C", AuthOOB
		res.ACSRenderingType = rendering(q.DeviceChannel, "04")
	case len(otpChannels(c)) > 1:
		ch.Step = "select" // single-select: where to send the passcode
		res.TransStatus, res.AuthenticationType = "C", AuthOTP
		res.ACSRenderingType = rendering(q.DeviceChannel, "02")
	default:
		if err := a.sendOTP(ctx, ch, otpChannels(c)[0]); err != nil {
			return no("U", ReasonSecurity)
		}
		res.TransStatus, res.AuthenticationType = "C", AuthOTP
		res.ACSRenderingType = rendering(q.DeviceChannel, "01")
	}
	var sess *AppSession
	if res.TransStatus == "C" {
		res.ACSChallengeMandated, res.ACSURL = "Y", a.cfg.ChallengeURL
		if q.DeviceChannel == "01" { // app: key agreement with the SDK, CReq/CRes encrypted
			if q.SDKEphemPubKey == nil || a.cfg.Signer == nil {
				return no("U", ReasonSecurity)
			}
			var signed string
			if sess, signed, err = NewAppSession(*q.SDKEphemPubKey, q.SDKReferenceNumber, a.cfg.ChallengeURL, a.cfg.Signer); err != nil {
				return ARes{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
			}
			ch.App, ch.Owner, res.ACSSignedContent, res.ACSURL = true, a.cfg.Instance, signed, ""
		}
	}
	a.mu.Lock()
	err = a.store.Create(ctx, ch)
	if err == nil && sess != nil {
		a.apps[ch.ACSTransID] = sess
	}
	a.mu.Unlock()
	if err != nil {
		slog.Error("3ds: challenge store", "acsTransID", ch.ACSTransID, "err", err)
		res = ARes{MessageType: res.MessageType, MessageVersion: res.MessageVersion, ThreeDSServerTransID: res.ThreeDSServerTransID,
			DSTransID: res.DSTransID, ACSTransID: res.ACSTransID, SDKTransID: res.SDKTransID}
		return no("U", ReasonSecurity)
	}
	slog.Info("3ds authentication", "acsTransID", ch.ACSTransID, "version", q.MessageVersion, "status", res.TransStatus, "step", ch.Step, "verdict", verdict)
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

func (a *ACS) sendOTP(ctx context.Context, ch *ChallengeState, channel string) error {
	otp := randomDigits(6)
	ch.OTPMAC, ch.Step, ch.Expires = a.otpMAC(ch.ACSTransID, otp), "otp", a.cfg.Now().Add(a.cfg.OTPTTL)
	if ch.OTPMAC == nil {
		return errors.New("security module unavailable for the passcode")
	}
	return a.otp.Send(ctx, ch.AReq.AcctNumber, ch.Card, channel, otp)
}

// storeErr maps a store outcome for a request: the challenge vanished or changed under us (finished elsewhere) is the
// requestor's problem (400); anything else is the store's (500).
func storeErr(err error) error {
	if errors.Is(err, ErrNoChallenge) || errors.Is(err, ErrConflict) {
		return fmt.Errorf("%w: challenge already completed or changed", ErrBadRequest)
	}
	return err
}

// Challenge handles a CReq (app or browser).
func (a *ACS) Challenge(ctx context.Context, q CReq) (CRes, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if q.MessageType != "CReq" {
		return CRes{}, fmt.Errorf("%w: unknown challenge", ErrBadRequest)
	}
	ch, err := a.store.Get(ctx, q.ACSTransID)
	if err != nil && !errors.Is(err, ErrNoChallenge) {
		return CRes{}, err
	}
	if err != nil || ch.AReq.ThreeDSServerTransID != q.ThreeDSServerTransID || ch.Step == "decoupled" || ch.Step == "spc" {
		return CRes{}, fmt.Errorf("%w: unknown challenge", ErrBadRequest)
	}
	res := CRes{MessageType: "CRes", MessageVersion: ch.Version, ThreeDSServerTransID: q.ThreeDSServerTransID, ACSTransID: q.ACSTransID,
		SDKTransID: q.SDKTransID, ChallengeCompletionInd: "N"}
	authType := AuthOTP
	if ch.Step == "oob" {
		authType = AuthOOB
	}
	finish := func(status, reason string, result, factor int) (CRes, error) {
		rr, err := a.finishLocked(ctx, ch, status, reason, authType, result, factor, q.ChallengeCancel)
		if err != nil {
			return CRes{}, storeErr(err)
		}
		res.ChallengeCompletionInd, res.TransStatus = "Y", rr.TransStatus
		return res, nil
	}
	// save persists the challenge's new state before an intermediate CRes goes out.
	save := func() (CRes, error) {
		if err := a.store.Update(ctx, ch); err != nil {
			return CRes{}, storeErr(err)
		}
		return res, nil
	}
	switch {
	case q.ChallengeCancel != "":
		return finish("N", ReasonAuthFailed, 0, 0)
	case a.cfg.Now().After(ch.Expires):
		return finish("N", ReasonTimedOut, 0, 0)
	}
	switch ch.Step {
	case "fido":
		switch {
		case q.FIDOFallback == "Y":
			return a.fidoFallbackLocked(ctx, ch, res)
		case q.FIDOAssertion != "":
			_, err := a.verifyAssertion(ctx, ch, []byte(q.FIDOAssertion))
			switch {
			case err == nil:
				return finish("Y", "", threeds.ResultChallenge, SecondFactorFIDO)
			case errors.Is(err, errFIDOFallback):
				return a.fidoFallbackLocked(ctx, ch, res)
			case errors.Is(err, errFIDOCounter):
				return finish("N", ReasonSecurity, 0, 0)
			case errors.Is(err, errFIDOVerify):
				slog.Info("3ds FIDO assertion rejected", "acsTransID", ch.ACSTransID, "err", err)
				ch.Attempts++
				return finish("N", ReasonAuthFailed, 0, 0)
			default:
				return CRes{}, err
			}
		}
		res.ACSUIType, res.ChallengeInfoHeader = "05", "Verify your purchase"
		res.ChallengeInfoText, res.FIDO = "Confirm with your passkey (fingerprint, face or screen lock).", a.fidoRequest(ch)
		return res, nil
	case "select":
		chs := otpChannels(ch.Card)
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
		return save()
	case "oob":
		switch {
		case ch.OOB == "approved":
			return finish("Y", "", threeds.ResultChallenge, 2)
		case ch.OOB == "declined":
			return finish("N", ReasonAuthFailed, 0, 0)
		}
		res.ACSUIType, res.ChallengeInfoHeader = "04", "Approve in your DIFME app"
		res.ChallengeInfoText, res.OOBAppLabel, res.OOBContinueLabel = "We sent a request to your DIFME app. Approve it, then continue.", "DIFME", "Continue"
		return res, nil
	}
	// step "otp"
	if q.ResendChallenge == "Y" {
		if err := a.sendOTP(ctx, ch, otpChannels(ch.Card)[0]); err != nil {
			return finish("U", ReasonSecurity, 0, 0)
		}
		res.ACSUIType, res.ChallengeInfoText = "01", "We sent you a new code"
		return save()
	}
	if q.ChallengeDataEntry == "" {
		res.ACSUIType, res.ChallengeInfoHeader, res.ChallengeInfoText, res.ResendInformationLabel = "01", "Verify your purchase", "Enter the code we sent you", "Send a new code"
		return res, nil
	}
	ch.Attempts++
	if got := a.otpMAC(ch.ACSTransID, q.ChallengeDataEntry); got != nil && hmac.Equal(ch.OTPMAC, got) {
		return finish("Y", "", threeds.ResultChallenge, 1)
	}
	if ch.Attempts >= a.cfg.MaxAttempts {
		return finish("N", ReasonMaxChallenge, 0, 0)
	}
	res.ACSUIType, res.ChallengeInfoText = "01", fmt.Sprintf("Incorrect code, %d attempt(s) left", a.cfg.MaxAttempts-ch.Attempts)
	return save()
}

// OOBResult records the DIFME app's answer for an out-of-band or decoupled authentication. In production the app
// approves after biometric/device authentication and signs the answer with its device key; this call comes from the
// app backend over the mesh (mTLS, AuthorizationPolicy). Decoupled authentications finish here (RReq sent).
func (a *ACS) OOBResult(ctx context.Context, acsTransID string, approved bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, err := a.store.Get(ctx, acsTransID)
	if err != nil && !errors.Is(err, ErrNoChallenge) {
		return err
	}
	if err != nil || (ch.Step != "oob" && ch.Step != "decoupled") {
		return fmt.Errorf("%w: no out-of-band authentication pending", ErrBadRequest)
	}
	switch {
	case a.cfg.Now().After(ch.Expires):
		_, err = a.finishLocked(ctx, ch, "N", ReasonDecoupledExp, AuthDecoupled, 0, 0, "")
	case ch.Step == "decoupled" && approved:
		_, err = a.finishLocked(ctx, ch, "Y", "", AuthDecoupled, threeds.ResultChallenge, 2, "")
	case ch.Step == "decoupled":
		_, err = a.finishLocked(ctx, ch, "N", ReasonAuthFailed, AuthDecoupled, 0, 0, "")
	default:
		ch.OOB = map[bool]string{true: "approved", false: "declined"}[approved]
		err = a.store.Update(ctx, ch)
	}
	if err != nil {
		return storeErr(err)
	}
	return nil
}

// abandonedAfter is how long an expired, never-finished challenge (cardholder walked away) stays in the store before
// Expire removes it without an RReq; until then a late CReq still gets its N/14 answer.
const abandonedAfter = 24 * time.Hour

// Expire finishes decoupled authentications past their maximum time and removes long-abandoned challenges (call
// periodically).
func (a *ACS) Expire(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.store.List(ctx)
	if err != nil {
		slog.Error("3ds: challenge store", "err", err)
		return
	}
	now := a.cfg.Now()
	for _, ch := range all {
		switch {
		case ch.Step == "decoupled" && now.After(ch.Expires):
			if _, err := a.finishLocked(ctx, ch, "N", ReasonDecoupledExp, AuthDecoupled, 0, 0, ""); err != nil {
				slog.Error("3ds: expire", "acsTransID", ch.ACSTransID, "err", err)
			}
		case now.After(ch.Expires.Add(abandonedAfter)):
			if err := a.store.Delete(ctx, ch.ACSTransID, ch.Rev); err == nil {
				delete(a.apps, ch.ACSTransID)
			}
		}
	}
}

// Recover ends, with transStatus U (reason 09), the app-channel challenges this instance (Config.Instance) started
// before a restart: their session keys lived only in the old process, so CReq/CRes can no longer be decrypted.
// Call once at start-up with a durable store. Returns how many were ended.
func (a *ACS) Recover(ctx context.Context) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.store.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ch := range all {
		if ch.App && ch.Owner == a.cfg.Instance && a.apps[ch.ACSTransID] == nil {
			if _, err := a.finishLocked(ctx, ch, "U", ReasonSecurity, authTypeOf(ch), 0, 0, ""); err == nil {
				n++
			}
		}
	}
	return n, nil
}

func authTypeOf(ch *ChallengeState) string {
	switch ch.Step {
	case "oob":
		return AuthOOB
	case "decoupled":
		return AuthDecoupled
	}
	return AuthOTP
}

// finishLocked ends a challenge: it removes it from the store (which fails if another request or replica changed or
// finished it), then builds the CAVV on success and sends the RReq to the directory server. Caller holds a.mu.
func (a *ACS) finishLocked(ctx context.Context, ch *ChallengeState, status, reason, authType string, result, factor int, cancel string) (RReq, error) {
	if err := a.store.Delete(ctx, ch.ACSTransID, ch.Rev); err != nil {
		return RReq{}, err
	}
	delete(a.apps, ch.ACSTransID)
	rr := RReq{MessageType: "RReq", MessageVersion: ch.Version, MessageCategory: ch.AReq.MessageCategory, ThreeDSServerTransID: ch.AReq.ThreeDSServerTransID,
		DSTransID: ch.AReq.DSTransID, ACSTransID: ch.ACSTransID, TransStatus: status, TransStatusReason: reason,
		InteractionCounter: fmt.Sprintf("%02d", ch.Attempts), AuthenticationType: authType, ChallengeCancel: cancel}
	if ch.FIDO != nil && ch.FIDO.Used != "" && ch.Version == "2.3.1" {
		rr.AuthenticationMethod = []string{ch.FIDO.Used}
	}
	if status == "Y" {
		v, _, err := threeds.Build(ctx, a.hsm, ch.AReq.AcctNumber, result, factor)
		if err != nil {
			slog.Error("3ds: security module", "err", err)
			rr.TransStatus, rr.TransStatusReason = "U", ReasonSecurity
		} else {
			rr.AuthenticationValue, rr.ECI = v, "05"
		}
	}
	if err := a.results.Send(ctx, rr); err != nil {
		slog.Error("3ds: RReq", "acsTransID", ch.ACSTransID, "err", err)
	}
	slog.Info("3ds challenge", "acsTransID", ch.ACSTransID, "status", rr.TransStatus, "reason", reason, "type", authType, "attempts", ch.Attempts)
	return rr, nil
}

// NotificationURL returns where a browser challenge's CRes goes (the AReq's notificationURL).
func (a *ACS) notificationURL(ctx context.Context, acsTransID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ch, err := a.store.Get(ctx, acsTransID); err == nil {
		return ch.AReq.NotificationURL
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
	sess := a.apps[hdr.Kid]
	if sess == nil {
		// Not in this process's memory: if the store still has it as an app-channel challenge, its session key was
		// lost (restart, or another replica): the channel cannot continue, so the challenge ends with U.
		if ch, err := a.store.Get(ctx, hdr.Kid); err == nil && ch.App {
			if _, err := a.finishLocked(ctx, ch, "U", ReasonSecurity, authTypeOf(ch), 0, 0, ""); err == nil {
				a.mu.Unlock()
				return "", fmt.Errorf("%w: app session lost; challenge ended (transStatus U)", ErrBadRequest)
			}
		}
	}
	a.mu.Unlock()
	if sess == nil {
		return "", fmt.Errorf("%w: unknown app challenge", ErrBadRequest)
	}
	pt, enc, err := sess.DecryptCReq(jwe)
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
	return sess.EncryptCRes(out, enc, hdr.Kid)
}

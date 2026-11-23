package acs

// FIDO / WebAuthn and Secure Payment Confirmation (SPC) authentication (EMV 3DS 2.3.1).
//
// EMVCo's specification text is not freely redistributable, so the codes and field names below come from public
// sources; each use names its source with one of these tags:
//
//	[EMVCO-SPC] EMVCo knowledge hub, "WebAuthn and SPC" (https://www.emvco.com/?p=112866): issuer-initiated SPC is a
//	            browser challenge, ARes transStatus C with Authentication Method 14 (SPC), the ACS calls SPC in the
//	            challenge iframe (allow="payment *; publickey-credentials-get *"). Merchant-initiated SPC: AReq #1 with
//	            "3DS Requestor SPC Support" = Y; ARes #1 transStatus S with "WebAuthn Credential List" and "SPC
//	            Transaction Data" (challenge, challenge information text, currency, value, display name, icon, payee
//	            name, payee origin, timeout in ms, ...); the requestor calls SPC; AReq #2 (new threeDSServerTransID)
//	            carries the FIDO assertion data in the 3DS Requestor Authentication Information with 3DS Requestor
//	            Authentication Method 09, and the 3DS Requestor Prior Transaction Authentication Information with
//	            prior reference = ACS Transaction ID of ARes #1 and prior method 05 (SPC). The ACS checks the
//	            assertion signature and the consistency of AReq #1 and #2, then answers (Y expected; C allowed).
//	[RAVELIN]   Ravelin 3DS API reference (https://developer.ravelin.com/psp/api/endpoints/3d-secure/result/ and
//	            .../guides/3d-secure/3ds-231-api-changes/): authenticationMethod (2.3.1) 01 static passcode, 02 SMS OTP,
//	            ... 12 decoupled, 13 WebAuthn, 14 SPC, 15 behavioural biometrics, 16 electronic ID; authenticationType
//	            (01 static, 02 dynamic, 03 OOB, 04 decoupled) deprecated in its favour; JSON names
//	            threeDSRequestorSpcSupport, payeeOrigin, webAuthnCredList, spcTransData.
//	[NSOFTWARE] nsoftware, "What's new in 3DS 2.3.1" (https://www.nsoftware.com/kb/articles/3dsecure-whatsnew-231):
//	            ACS Information Indicator 06 WebAuthn authentication supported, 07 SPC authentication supported; the
//	            WebAuthn credential list carries a relying party id.
//	[FIDO-TN]   FIDO Alliance, "FIDO Authentication and EMV 3-D Secure" technical note, 2020-09-01: 3DS Requestor
//	            Authentication Method 06 (login at the requestor with a FIDO authenticator), 07 (FIDO, assurance data
//	            signed); 3DS Requestor Authentication Data = "FIDO Authentication Data" serialised as a JSON string:
//	            authTime, rpId or appId, FIDOAuthenticatorReferences[publicKey, aaguid|aaid, usedForThisTransaction,
//	            up, uv].
//	[EMV-220]   EMV 3DS 2.2.0 (publicly downloadable from EMVCo, cited by [FIDO-TN]) JSON names of
//	            threeDSRequestorAuthenticationInfo {threeDSReqAuthMethod, threeDSReqAuthTimestamp, threeDSReqAuthData}
//	            and threeDSRequestorPriorAuthenticationInfo {threeDSReqPriorAuthData, threeDSReqPriorAuthMethod,
//	            threeDSReqPriorAuthTimestamp, threeDSReqPriorRef}; purchaseExponent.
//	[W3C-SPC]   W3C Secure Payment Confirmation (https://www.w3.org/TR/secure-payment-confirmation/): payment method
//	            "secure-payment-confirmation"; request members challenge, rpId, credentialIds, instrument
//	            {displayName, icon, iconMustBeShown}, payeeName, payeeOrigin, timeout; registration extension
//	            payment {isPayment: true}; clientDataJSON type "payment.get" with member payment {rpId, topOrigin,
//	            payeeName, payeeOrigin, total {currency, value}, instrument}; §9.1 relying-party verification; SPC
//	            hard-codes userVerification "required".
//	[WEBAUTHN]  W3C Web Authentication Level 3 (https://www.w3.org/TR/webauthn-3/): §7.1 registering a credential,
//	            §7.2 verifying an assertion (incl. the signature-counter step), §5.8.1 client data, JSON
//	            serialisation of PublicKeyCredential (toJSON()).
//
// Not public, so DIFME's choice (marked "unverified" where used): the exact JSON keys inside spcTransData and
// webAuthnCredList entries, and the encoding of the SPC assertion in threeDSReqAuthData (here: the [WEBAUTHN] JSON
// serialisation of the PublicKeyCredential, as a string).
//
// WebAuthn signature checks, authenticator-data parsing and attestation verification use github.com/go-webauthn/webauthn
// (BSD-3-Clause). Client-data checks are done here because SPC's "payment.get" client data (with its payment member)
// and the merchant-initiated origin rules are outside that library's assertion ceremony.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// EMV 3DS 2.3.1 codes for FIDO / SPC.
const (
	MethodWebAuthn = "13" // authenticationMethod: WebAuthn [RAVELIN]
	MethodSPC      = "14" // authenticationMethod: SPC [RAVELIN], [EMVCO-SPC]

	ReqAuthFIDO         = "06" // threeDSReqAuthMethod: login at the requestor with a FIDO authenticator [FIDO-TN]
	ReqAuthFIDOSigned   = "07" // threeDSReqAuthMethod: FIDO authenticator, FIDO assurance data signed [FIDO-TN]
	ReqAuthSPCAssertion = "09" // threeDSReqAuthMethod: SPC/FIDO assertion data in AReq #2 [EMVCO-SPC]
	PriorAuthSPC        = "05" // threeDSReqPriorAuthMethod: SPC [EMVCO-SPC]

	StatusSPC = "S" // transStatus: merchant-initiated SPC, the requestor calls SPC and sends AReq #2 [EMVCO-SPC]

	ACSInfoWebAuthn = "06" // acsInfoInd: WebAuthn authentication supported [NSOFTWARE]
	ACSInfoSPC      = "07" // acsInfoInd: SPC authentication supported [NSOFTWARE]

	// SecondFactorFIDO is the CAVV second-factor result code for a FIDO assertion (DIFME CAVV layout, internal/threeds:
	// 01 OTP, 02 app out-of-band, 03 FIDO/WebAuthn/SPC).
	SecondFactorFIDO = 3

	ceremonyGet = "webauthn.get" // [WEBAUTHN] §5.8.1
	ceremonySPC = "payment.get"  // [W3C-SPC] §9.1 step 11
)

// FIDOConfig turns on WebAuthn / SPC. The ACS is the WebAuthn relying party (the issuer's domain): credentials are
// registered by the issuer app against RPID and asserted in the ACS's browser challenge page or, for SPC, by the 3DS
// Requestor's page.
type FIDOConfig struct {
	RPID   string // WebAuthn relying party id, e.g. "acs.difme.example" (empty: FIDO off)
	RPName string
	// Origins accepted in clientDataJSON for registration and for the ACS's challenge page: https origins (the ACS
	// page, the issuer web app) and opaque app origins (e.g. "android:apk-key-hash:...").
	Origins []string
	// TrustedRequestorRPIDs are 3DS Requestor relying-party ids whose FIDO Authentication Data (threeDSReqAuthMethod
	// 06/07, [FIDO-TN]) the ACS records as trusted risk input.
	TrustedRequestorRPIDs []string
	Timeout               time.Duration // ceremony timeout (default 3 minutes)
	Icon                  string        // SPC instrument icon (https or data URL)
}

func (a *ACS) fidoOn() bool { return a.cfg.FIDO.RPID != "" }

// FIDOCredential is a registered WebAuthn credential: only its id, public key (COSE_Key) and signature counter
// (plus whether it was created with the SPC payment extension). Never the PAN: it is filed under the ACS's card
// reference (HMAC of the PAN in the security module, the same reference FRM gets).
type FIDOCredential struct {
	ID        []byte    `json:"id"`
	PublicKey []byte    `json:"publicKey"`
	SignCount uint32    `json:"signCount"`
	SPC       bool      `json:"spc,omitempty"`
	Created   time.Time `json:"created"`
}

var (
	ErrNoCredential      = errors.New("no such FIDO credential")
	ErrCredentialExists  = errors.New("FIDO credential already registered")
	errFIDOFallback      = errors.New("FIDO not usable: fall back to OTP")
	errFIDOCounter       = errors.New("FIDO signature counter did not increase (cloned authenticator or replay)")
	errFIDOVerify        = errors.New("FIDO assertion rejected")
	defaultSPCIcon       = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="32" height="20"><rect width="32" height="20" rx="3" fill="#1a3d7c"/></svg>`))
	registrationLifetime = 5 * time.Minute
)

// CredentialStore keeps registered WebAuthn credentials by card reference. A credential id is unique across cards
// ([WEBAUTHN] §7.1: an id already registered is refused). UpdateSignCount succeeds only when the stored counter is
// still old (two replicas cannot both accept the same counter value).
type CredentialStore interface {
	AddCredential(ctx context.Context, cardRef string, c FIDOCredential) error
	Credentials(ctx context.Context, cardRef string) ([]FIDOCredential, error)
	UpdateSignCount(ctx context.Context, cardRef string, id []byte, old, new uint32) error
	DeleteCredential(ctx context.Context, cardRef string, id []byte) error
}

// MemoryCredentials is the in-process credential store (tests, development).
type MemoryCredentials struct {
	mu sync.Mutex
	m  map[string]memCred // by credential id
}

type memCred struct {
	ref string
	c   FIDOCredential
}

func NewMemoryCredentials() *MemoryCredentials { return &MemoryCredentials{m: map[string]memCred{}} }

func (s *MemoryCredentials) AddCredential(_ context.Context, ref string, c FIDOCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[string(c.ID)]; ok {
		return ErrCredentialExists
	}
	c.ID, c.PublicKey = slices.Clone(c.ID), slices.Clone(c.PublicKey)
	s.m[string(c.ID)] = memCred{ref, c}
	return nil
}

func (s *MemoryCredentials) Credentials(_ context.Context, ref string) ([]FIDOCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []FIDOCredential
	for _, k := range slices.Sorted(maps.Keys(s.m)) {
		if e := s.m[k]; e.ref == ref {
			c := e.c
			c.ID, c.PublicKey = slices.Clone(c.ID), slices.Clone(c.PublicKey)
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *MemoryCredentials) UpdateSignCount(_ context.Context, ref string, id []byte, old, new uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[string(id)]
	switch {
	case !ok || e.ref != ref:
		return ErrNoCredential
	case e.c.SignCount != old:
		return ErrConflict
	}
	e.c.SignCount = new
	s.m[string(id)] = e
	return nil
}

func (s *MemoryCredentials) DeleteCredential(_ context.Context, ref string, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[string(id)]; !ok || e.ref != ref {
		return ErrNoCredential
	}
	delete(s.m, string(id))
	return nil
}

// FIDOPending is the FIDO part of a pending challenge (ChallengeState.FIDO).
type FIDOPending struct {
	Challenge   []byte   `json:"challenge"`           // random, single use
	Credentials [][]byte `json:"credentials"`         // ids offered (allowCredentials / credentialIds)
	SPC         bool     `json:"spc,omitempty"`       // SPC offered (payment, a credential registered for payment)
	Instrument  string   `json:"instrument"`          // SPC instrument display name shown (and checked)
	Merchant    bool     `json:"merchant,omitempty"`  // merchant-initiated SPC (ARes S, assertion comes in AReq #2)
	Used        string   `json:"used,omitempty"`      // authenticationMethod that succeeded (13/14)
	TopOrigin   string   `json:"topOrigin,omitempty"` // recorded from the assertion (merchant page)
}

func (f *FIDOPending) clone() *FIDOPending {
	if f == nil {
		return nil
	}
	cp := *f
	cp.Challenge = slices.Clone(f.Challenge)
	cp.Credentials = make([][]byte, len(f.Credentials))
	for i, c := range f.Credentials {
		cp.Credentials[i] = slices.Clone(c)
	}
	return &cp
}

// FIDORequest is what the browser challenge page needs to call navigator.credentials.get or the SPC PaymentRequest
// ([WEBAUTHN] PublicKeyCredentialRequestOptions, [W3C-SPC] SecurePaymentConfirmationRequest + PaymentDetailsInit).
type FIDORequest struct {
	Challenge     string        `json:"challenge"` // base64url
	RPID          string        `json:"rpId"`
	CredentialIDs []string      `json:"credentialIds"` // base64url
	SPC           bool          `json:"spc"`
	Currency      string        `json:"currency,omitempty"` // ISO 4217 alphabetic (PaymentCurrencyAmount)
	Value         string        `json:"value,omitempty"`    // decimal major units
	PayeeName     string        `json:"payeeName,omitempty"`
	PayeeOrigin   string        `json:"payeeOrigin,omitempty"`
	Instrument    SPCInstrument `json:"instrument"`
	Timeout       int64         `json:"timeout"` // ms
}

// SPCInstrument is [W3C-SPC] PaymentCredentialInstrument.
type SPCInstrument struct {
	DisplayName     string `json:"displayName"`
	Icon            string `json:"icon"`
	IconMustBeShown bool   `json:"iconMustBeShown"`
}

// SPCTransData is the ARes spcTransData object of the merchant-initiated flow. Members follow [EMVCO-SPC] table 4.3;
// the JSON keys are DIFME's camelCase of those names (unverified: the 2.3.1 key names are not public).
type SPCTransData struct {
	Challenge         string `json:"challenge"`
	ChallengeInfoText string `json:"challengeInfoText,omitempty"`
	Currency          string `json:"currency"`
	Value             string `json:"value"`
	DisplayName       string `json:"displayName"`
	Icon              string `json:"icon"`
	PayeeName         string `json:"payeeName,omitempty"`
	PayeeOrigin       string `json:"payeeOrigin,omitempty"`
	Timeout           int64  `json:"timeout"` // ms [EMVCO-SPC]
}

// WebAuthnCred is one webAuthnCredList entry: credential id and relying party id ([NSOFTWARE] lists a relying-party
// id on the list; the keys are DIFME's, unverified).
type WebAuthnCred struct {
	Credential string `json:"webAuthnCred"` // base64url credential id
	RPID       string `json:"rpId"`
}

// ReqAuthInfo is threeDSRequestorAuthenticationInfo [EMV-220].
type ReqAuthInfo struct {
	Method    string `json:"threeDSReqAuthMethod"`
	Timestamp string `json:"threeDSReqAuthTimestamp,omitempty"` // YYYYMMDDHHMM
	Data      string `json:"threeDSReqAuthData,omitempty"`
}

// PriorAuthInfo is threeDSRequestorPriorAuthenticationInfo [EMV-220].
type PriorAuthInfo struct {
	Data      string `json:"threeDSReqPriorAuthData,omitempty"`
	Method    string `json:"threeDSReqPriorAuthMethod,omitempty"`
	Timestamp string `json:"threeDSReqPriorAuthTimestamp,omitempty"`
	Ref       string `json:"threeDSReqPriorRef,omitempty"`
}

func (a *ACS) fidoTimeout() time.Duration {
	if a.cfg.FIDO.Timeout > 0 {
		return a.cfg.FIDO.Timeout
	}
	return 3 * time.Minute
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func last4(pan string) string { return pan[len(pan)-4:] }

// newFIDOPending prepares a FIDO challenge for a card's credentials.
func newFIDOPending(q AReq, creds []FIDOCredential, merchant bool) *FIDOPending {
	f := &FIDOPending{Challenge: make([]byte, 32), Instrument: "DIFME card •••• " + last4(q.AcctNumber), Merchant: merchant}
	_, _ = rand.Read(f.Challenge)
	for _, c := range creds {
		if merchant && !c.SPC {
			continue
		}
		f.Credentials = append(f.Credentials, slices.Clone(c.ID))
		f.SPC = f.SPC || (c.SPC && q.MessageCategory == "01")
	}
	return f
}

func (a *ACS) fidoRequest(ch *ChallengeState) *FIDORequest {
	f := ch.FIDO
	r := &FIDORequest{Challenge: b64u(f.Challenge), RPID: a.cfg.FIDO.RPID, SPC: f.SPC, Timeout: a.fidoTimeout().Milliseconds(),
		Instrument: SPCInstrument{DisplayName: f.Instrument, Icon: a.spcIcon()}}
	for _, id := range f.Credentials {
		r.CredentialIDs = append(r.CredentialIDs, b64u(id))
	}
	if f.SPC {
		amount, _ := strconv.ParseInt(ch.AReq.PurchaseAmount, 10, 64)
		r.Currency, r.Value = currencyAlpha(ch.AReq.PurchaseCurrency), formatMinor(amount, exponent(ch.AReq))
		r.PayeeName, r.PayeeOrigin = ch.AReq.MerchantName, ch.AReq.PayeeOrigin
	}
	return r
}

func (a *ACS) spcIcon() string {
	if a.cfg.FIDO.Icon != "" {
		return a.cfg.FIDO.Icon
	}
	return defaultSPCIcon
}

func (a *ACS) spcTransData(ch *ChallengeState) (*SPCTransData, []WebAuthnCred) {
	r := a.fidoRequest(ch)
	var list []WebAuthnCred
	for _, id := range r.CredentialIDs {
		list = append(list, WebAuthnCred{Credential: id, RPID: r.RPID})
	}
	return &SPCTransData{Challenge: r.Challenge, ChallengeInfoText: "Confirm this purchase with your DIFME card passkey", Currency: r.Currency,
		Value: r.Value, DisplayName: r.Instrument.DisplayName, Icon: r.Instrument.Icon, PayeeName: r.PayeeName, PayeeOrigin: r.PayeeOrigin,
		Timeout: r.Timeout}, list
}

// exponent is the AReq's purchaseExponent [EMV-220] (default 2).
func exponent(q AReq) int {
	if e, err := strconv.Atoi(q.PurchaseExponent); err == nil && e >= 0 && e <= 4 {
		return e
	}
	return 2
}

func formatMinor(minor int64, exp int) string {
	if exp == 0 {
		return strconv.FormatInt(minor, 10)
	}
	s := fmt.Sprintf("%0*d", exp+1, minor)
	return s[:len(s)-exp] + "." + s[len(s)-exp:]
}

// parseMinor reads a PaymentCurrencyAmount value ("10.5", "10.50") as minor units.
func parseMinor(v string, exp int) (int64, bool) {
	whole, frac, _ := strings.Cut(v, ".")
	if whole == "" || len(frac) > exp || strings.Trim(whole+frac, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(whole+frac+strings.Repeat("0", exp-len(frac)), 10, 64)
	return n, err == nil
}

// clientData is [WEBAUTHN] CollectedClientData plus the [W3C-SPC] payment member.
type clientData struct {
	Type        string   `json:"type"`
	Challenge   string   `json:"challenge"`
	Origin      string   `json:"origin"`
	CrossOrigin bool     `json:"crossOrigin"`
	TopOrigin   string   `json:"topOrigin"`
	Payment     *spcData `json:"payment"`
}

// spcData is [W3C-SPC] CollectedClientAdditionalPaymentData.
type spcData struct {
	RPID        string `json:"rpId"`
	TopOrigin   string `json:"topOrigin"`
	PayeeName   string `json:"payeeName"`
	PayeeOrigin string `json:"payeeOrigin"`
	Total       struct {
		Currency string `json:"currency"`
		Value    string `json:"value"`
	} `json:"total"`
	Instrument struct {
		DisplayName string `json:"displayName"`
		Icon        string `json:"icon"`
	} `json:"instrument"`
}

func sameOrigin(a, b string) bool {
	return a != "" && strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func (a *ACS) originAllowed(o string) bool {
	return slices.ContainsFunc(a.cfg.FIDO.Origins, func(x string) bool { return sameOrigin(x, o) })
}

// verifyAssertion checks a WebAuthn or SPC assertion (JSON PublicKeyCredential) against the pending FIDO challenge,
// following [WEBAUTHN] §7.2 with the [W3C-SPC] §9.1 changes, and advances the credential's signature counter. It
// returns the authenticationMethod (13/14). errFIDOFallback: the credential is not one of this card's (OTP next);
// errFIDOCounter: the counter did not increase; other errors: the assertion is not valid for this transaction.
// Caller holds a.mu.
func (a *ACS) verifyAssertion(ctx context.Context, ch *ChallengeState, raw []byte) (string, error) {
	f := ch.FIDO
	p, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFIDOVerify, err)
	}
	// step 5 / [W3C-SPC] §9.1: the credential must be one of those offered for this transaction
	if !slices.ContainsFunc(f.Credentials, func(id []byte) bool { return bytes.Equal(id, p.RawID) }) {
		return "", errFIDOFallback
	}
	creds, err := a.creds.Credentials(ctx, ch.CardRef)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(creds, func(c FIDOCredential) bool { return bytes.Equal(c.ID, p.RawID) })
	if i < 0 {
		return "", errFIDOFallback // removed since the challenge started
	}
	cred := creds[i]
	cdj := p.Raw.AssertionResponse.ClientDataJSON
	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return "", fmt.Errorf("%w: clientDataJSON", errFIDOVerify)
	}
	method := MethodWebAuthn
	switch {
	case cd.Type == ceremonySPC && f.SPC && cred.SPC: // [W3C-SPC] §9.1 step 11
		method = MethodSPC
	case cd.Type == ceremonyGet && !f.Merchant: // [WEBAUTHN] §7.2 step 11
	default:
		return "", fmt.Errorf("%w: client data type %q", errFIDOVerify, cd.Type)
	}
	// step 12: challenge
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(b64u(f.Challenge))) != 1 {
		return "", fmt.Errorf("%w: challenge", errFIDOVerify)
	}
	// step 13: origin. ACS challenge page: one of the configured origins. Merchant-initiated SPC: the requestor's page
	// calls SPC as the top-level document, so origin = payment.topOrigin (an https origin) ([W3C-SPC] §9.1).
	if f.Merchant {
		if cd.Payment == nil || !strings.HasPrefix(cd.Origin, "https://") || !sameOrigin(cd.Origin, cd.Payment.TopOrigin) {
			return "", fmt.Errorf("%w: origin %q", errFIDOVerify, cd.Origin)
		}
	} else if !a.originAllowed(cd.Origin) {
		return "", fmt.Errorf("%w: origin %q", errFIDOVerify, cd.Origin)
	}
	if method == MethodSPC {
		if err := a.checkSPCData(ch, cd.Payment); err != nil {
			return "", err
		}
		f.TopOrigin = cd.Payment.TopOrigin
	} else if cd.CrossOrigin {
		f.TopOrigin = cd.TopOrigin // the 3DS Requestor page framing the ACS (recorded, not enforced)
	}
	// steps 15-17: rpIdHash, user verification ([W3C-SPC] hard-codes userVerification "required"); user presence for
	// WebAuthn (the SPC dialog is the user's consent, so its UP bit is not required).
	rpHash := sha256.Sum256([]byte(a.cfg.FIDO.RPID))
	if err := p.Response.AuthenticatorData.Verify(rpHash[:], nil, true, method == MethodWebAuthn); err != nil {
		return "", fmt.Errorf("%w: authenticator data: %v", errFIDOVerify, err)
	}
	// steps 19-20: signature over authenticatorData || SHA-256(clientDataJSON)
	key, err := webauthncose.ParsePublicKey(cred.PublicKey)
	if err != nil {
		return "", fmt.Errorf("%w: stored public key: %v", errFIDOVerify, err)
	}
	h := sha256.Sum256(cdj)
	if ok, err := webauthncose.VerifySignature(key, slices.Concat([]byte(p.Raw.AssertionResponse.AuthenticatorData), h[:]), p.Response.Signature); !ok || err != nil {
		return "", fmt.Errorf("%w: signature", errFIDOVerify)
	}
	// step 21: signature counter. Either non-zero and not greater than the stored value: possible clone / replay.
	n := p.Response.AuthenticatorData.Counter
	if (n != 0 || cred.SignCount != 0) && n <= cred.SignCount {
		return "", errFIDOCounter
	}
	if n != cred.SignCount {
		if err := a.creds.UpdateSignCount(ctx, ch.CardRef, cred.ID, cred.SignCount, n); err != nil {
			if errors.Is(err, ErrConflict) {
				return "", errFIDOCounter // another request advanced it first
			}
			return "", err
		}
	}
	f.Used = method
	return method, nil
}

// checkSPCData binds the transaction into the assertion: [W3C-SPC] §9.1 "after step 13" checks against what the ACS
// asked to be shown (AReq amount, currency, merchant, payee origin, instrument, rpId).
func (a *ACS) checkSPCData(ch *ChallengeState, p *spcData) error {
	bad := func(what string) error {
		return fmt.Errorf("%w: SPC %s does not match the transaction", errFIDOVerify, what)
	}
	if p == nil {
		return bad("payment data")
	}
	q := ch.AReq
	amount, _ := strconv.ParseInt(q.PurchaseAmount, 10, 64)
	got, ok := parseMinor(p.Total.Value, exponent(q))
	switch {
	case p.RPID != a.cfg.FIDO.RPID:
		return bad("rpId")
	case p.TopOrigin == "":
		return bad("topOrigin")
	case !strings.EqualFold(p.Total.Currency, currencyAlpha(q.PurchaseCurrency)):
		return bad("currency")
	case !ok || got != amount:
		return bad("amount")
	case p.PayeeName != q.MerchantName:
		return bad("payee name")
	case q.PayeeOrigin != "" && !sameOrigin(p.PayeeOrigin, q.PayeeOrigin):
		return bad("payee origin")
	case p.Instrument.DisplayName != ch.FIDO.Instrument:
		return bad("instrument")
	}
	return nil
}

// spcSecondAReq handles AReq #2 of merchant-initiated SPC [EMVCO-SPC]: the prior transaction (ARes #1, transStatus
// S) must be pending, for the same card, amount, currency and merchant, and the assertion must verify against its
// challenge. The prior challenge is consumed whatever the outcome (a replayed assertion finds nothing). Returns the
// method on success; errFIDOFallback when the prior transaction is unknown/expired or the credential is not the card's
// (the ACS then challenges with OTP); other errors fail the authentication.
func (a *ACS) spcSecondAReq(ctx context.Context, q AReq) (string, error) {
	prior := q.PriorAuthInfo
	if prior == nil || prior.Ref == "" || prior.Method != PriorAuthSPC {
		return "", errFIDOFallback
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, err := a.store.Get(ctx, prior.Ref)
	if err != nil || ch.Step != "spc" || ch.FIDO == nil {
		return "", errFIDOFallback
	}
	if err := a.store.Delete(ctx, ch.ACSTransID, ch.Rev); err != nil {
		return "", errFIDOFallback // consumed by a concurrent AReq #2
	}
	if a.cfg.Now().After(ch.Expires) {
		return "", errFIDOFallback
	}
	if subtle.ConstantTimeCompare([]byte(ch.AReq.AcctNumber), []byte(q.AcctNumber)) != 1 || ch.AReq.PurchaseAmount != q.PurchaseAmount ||
		ch.AReq.PurchaseCurrency != q.PurchaseCurrency || ch.AReq.MerchantName != q.MerchantName || ch.AReq.PayeeOrigin != q.PayeeOrigin {
		return "", fmt.Errorf("%w: AReq #2 does not match the SPC transaction", errFIDOVerify)
	}
	return a.verifyAssertion(ctx, ch, []byte(q.ReqAuthInfo.Data))
}

// FIDOAuthData is [FIDO-TN] "FIDO Authentication Data" (threeDSReqAuthData with threeDSReqAuthMethod 06/07).
type FIDOAuthData struct {
	AuthTime   string `json:"authTime"`
	RPID       string `json:"rpId,omitempty"`
	AppID      string `json:"appId,omitempty"`
	References []struct {
		PublicKey string `json:"publicKey"`
		AAGUID    string `json:"aaguid,omitempty"`
		AAID      string `json:"aaid,omitempty"`
		Used      bool   `json:"usedForThisTransaction"`
		UP        *bool  `json:"up,omitempty"`
		UV        *bool  `json:"uv,omitempty"`
	} `json:"FIDOAuthenticatorReferences"`
}

// requestorFIDO reads 06/07 FIDO Authentication Data. It reports whether a trusted requestor (rpId in
// FIDOConfig.TrustedRequestorRPIDs) verified the user with a FIDO authenticator (uv true) within the last 10 minutes,
// per the ACS processing the technical note recommends. The result is logged as risk input; EMV 3DS defines no
// transStatus outcome for it, so the decision is unchanged.
func (a *ACS) requestorFIDO(info *ReqAuthInfo) (bool, error) {
	var d FIDOAuthData
	if err := json.Unmarshal([]byte(info.Data), &d); err != nil {
		return false, fmt.Errorf("threeDSReqAuthData: FIDO Authentication Data JSON: %w", err)
	}
	if (d.RPID == "") == (d.AppID == "") || len(d.References) == 0 {
		return false, errors.New("threeDSReqAuthData: exactly one of rpId/appId and at least one authenticator required")
	}
	t, err := time.Parse(time.RFC3339, d.AuthTime)
	if err != nil {
		return false, fmt.Errorf("threeDSReqAuthData: authTime: %w", err)
	}
	id := d.RPID + d.AppID
	trusted := slices.Contains(a.cfg.FIDO.TrustedRequestorRPIDs, id) && a.cfg.Now().Sub(t) < 10*time.Minute && t.Before(a.cfg.Now().Add(time.Minute))
	for _, r := range d.References {
		if r.Used && r.UV != nil && *r.UV && r.PublicKey != "" {
			return trusted, nil
		}
	}
	return false, nil
}

// Registration (issuer app → ACS). The issuer app has authenticated the cardholder; it asks for creation options,
// runs navigator.credentials.create (or the platform API) and posts the attestation back. Registration state travels
// in a token MACed by the security module, so any ACS replica can finish it.

type regToken struct {
	Ref       string `json:"ref"`
	Challenge []byte `json:"challenge"`
	Expires   int64  `json:"exp"`
}

func (a *ACS) signToken(ctx context.Context, t regToken) (string, error) {
	b, _ := json.Marshal(t)
	payload := b64u(b)
	m, err := a.mac(ctx, "fido-reg|"+payload)
	if err != nil {
		return "", err
	}
	return payload + "." + b64u(m), nil
}

func (a *ACS) openToken(ctx context.Context, s string) (regToken, error) {
	payload, sig, _ := strings.Cut(s, ".")
	m, err := a.mac(ctx, "fido-reg|"+payload)
	if err != nil {
		return regToken{}, err
	}
	got, err1 := base64.RawURLEncoding.DecodeString(sig)
	b, err2 := base64.RawURLEncoding.DecodeString(payload)
	var t regToken
	if err1 != nil || err2 != nil || !hmac.Equal(got, m) || json.Unmarshal(b, &t) != nil || a.cfg.Now().Unix() > t.Expires {
		return regToken{}, fmt.Errorf("%w: registration token invalid or expired", ErrBadRequest)
	}
	return t, nil
}

// cardRefFor checks the card is known and usable and returns its reference.
func (a *ACS) cardRefFor(ctx context.Context, pan string) (string, Card, error) {
	if len(pan) < 12 {
		return "", Card{}, fmt.Errorf("%w: acctNumber required", ErrBadRequest)
	}
	c, found, err := a.cards.Card(ctx, pan)
	switch {
	case err != nil:
		return "", Card{}, err
	case !found || c.Status != "ACTIVE":
		return "", Card{}, fmt.Errorf("%w: card not found or not active", ErrBadRequest)
	}
	ref, err := a.payerRef(ctx, pan)
	return ref, c, err
}

var credParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// FIDORegistrationOptions returns PublicKeyCredentialCreationOptions ([WEBAUTHN] §5.4) with the SPC payment
// extension ([W3C-SPC] isPayment) and a registration token to send back with the attestation.
func (a *ACS) FIDORegistrationOptions(ctx context.Context, pan string) (map[string]any, error) {
	if !a.fidoOn() {
		return nil, fmt.Errorf("%w: FIDO not configured", ErrBadRequest)
	}
	ref, c, err := a.cardRefFor(ctx, pan)
	if err != nil {
		return nil, err
	}
	t := regToken{Ref: ref, Challenge: make([]byte, 32), Expires: a.cfg.Now().Add(registrationLifetime).Unix()}
	_, _ = rand.Read(t.Challenge)
	tok, err := a.signToken(ctx, t)
	if err != nil {
		return nil, err
	}
	uh, err := a.mac(ctx, "fido-user|"+pan) // stable opaque user handle per card
	if err != nil {
		return nil, err
	}
	existing, err := a.creds.Credentials(ctx, ref)
	if err != nil {
		return nil, err
	}
	exclude := []map[string]string{}
	for _, e := range existing {
		exclude = append(exclude, map[string]string{"type": "public-key", "id": b64u(e.ID)})
	}
	name := "DIFME card •••• " + last4(pan)
	if c.Holder != "" {
		name = c.Holder + " · " + name
	}
	return map[string]any{"registrationToken": tok, "publicKey": map[string]any{
		"rp":                     map[string]string{"id": a.cfg.FIDO.RPID, "name": cmp(a.cfg.FIDO.RPName, "DIFME card security")},
		"user":                   map[string]string{"id": b64u(uh[:16]), "name": "card-" + last4(pan), "displayName": name},
		"challenge":              b64u(t.Challenge),
		"pubKeyCredParams":       credParams,
		"timeout":                registrationLifetime.Milliseconds(),
		"excludeCredentials":     exclude,
		"authenticatorSelection": map[string]string{"userVerification": "required", "residentKey": "preferred"},
		"attestation":            "none",
		"extensions":             map[string]any{"payment": map[string]bool{"isPayment": true}},
	}}, nil
}

func cmp(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

// FIDORegister verifies a registration ([WEBAUTHN] §7.1: client data webauthn.create, challenge, origin, rpIdHash,
// user present and verified, algorithm offered, attestation statement) and stores the credential id and public key
// under the card reference. Returns the credential id (base64url).
func (a *ACS) FIDORegister(ctx context.Context, pan, token string, credential []byte) (string, error) {
	if !a.fidoOn() {
		return "", fmt.Errorf("%w: FIDO not configured", ErrBadRequest)
	}
	t, err := a.openToken(ctx, token)
	if err != nil {
		return "", err
	}
	ref, _, err := a.cardRefFor(ctx, pan)
	if err != nil {
		return "", err
	}
	if !hmac.Equal([]byte(ref), []byte(t.Ref)) {
		return "", fmt.Errorf("%w: registration token is for another card", ErrBadRequest)
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(credential)
	if err != nil {
		return "", fmt.Errorf("%w: credential: %v", ErrBadRequest, err)
	}
	var https, opaque []string
	for _, o := range a.cfg.FIDO.Origins {
		if strings.HasPrefix(o, "https://") || strings.HasPrefix(o, "http://") {
			https = append(https, o)
		} else {
			opaque = append(opaque, o)
		}
	}
	if _, err := pcc.Verify(b64u(t.Challenge), a.cfg.FIDO.RPID, https, opaque, nil, protocol.TopOriginExplicitVerificationMode, false, true, true,
		nil, credParams, protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		return "", fmt.Errorf("%w: registration rejected: %v", ErrBadRequest, err)
	}
	ad := pcc.Response.AttestationObject.AuthData
	c := FIDOCredential{ID: ad.AttData.CredentialID, PublicKey: ad.AttData.CredentialPublicKey, SignCount: ad.Counter, SPC: true, Created: a.cfg.Now().UTC()}
	if err := a.creds.AddCredential(ctx, ref, c); err != nil {
		if errors.Is(err, ErrCredentialExists) {
			return "", fmt.Errorf("%w: credential already registered", ErrBadRequest)
		}
		return "", err
	}
	slog.Info("3ds FIDO credential registered", "cardRef", ref, "credential", hex.EncodeToString(sha256Sum(c.ID))[:16])
	return b64u(c.ID), nil
}

// FIDODeregister removes a card's credential (lost device, cardholder request).
func (a *ACS) FIDODeregister(ctx context.Context, pan, credentialID string) error {
	id, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil {
		return fmt.Errorf("%w: credential id must be base64url", ErrBadRequest)
	}
	ref, err := a.payerRef(ctx, pan)
	if err != nil {
		return err
	}
	if err := a.creds.DeleteCredential(ctx, ref, id); errors.Is(err, ErrNoCredential) {
		return fmt.Errorf("%w: no such credential for this card", ErrBadRequest)
	} else if err != nil {
		return err
	}
	return nil
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// fidoFallbackLocked switches a "fido" challenge to a one-time passcode (no usable credential, or the browser
// declined WebAuthn/SPC): single-select when the card has several passcode channels, else the code is sent now.
// Caller holds a.mu.
func (a *ACS) fidoFallbackLocked(ctx context.Context, ch *ChallengeState, res CRes) (CRes, error) {
	ch.FIDO = nil
	chs := otpChannels(ch.Card)
	res.ChallengeInfoHeader = "Verify your purchase"
	if len(chs) > 1 {
		ch.Step = "select"
		res.ACSUIType, res.ChallengeInfoText = "02", "Where should we send your code?"
		for _, c := range chs {
			res.ChallengeSelectInfo = append(res.ChallengeSelectInfo, Choice{c: map[string]string{"sms": "Text message", "email": "Email"}[c]})
		}
	} else {
		if err := a.sendOTP(ctx, ch, chs[0]); err != nil {
			rr, err := a.finishLocked(ctx, ch, "U", ReasonSecurity, AuthOTP, 0, 0, "")
			if err != nil {
				return CRes{}, storeErr(err)
			}
			res.ChallengeCompletionInd, res.TransStatus = "Y", rr.TransStatus
			return res, nil
		}
		res.ACSUIType, res.ChallengeInfoText, res.ResendInformationLabel = "01", "Enter the code we sent you", "Send a new code"
	}
	if err := a.store.Update(ctx, ch); err != nil {
		return CRes{}, storeErr(err)
	}
	slog.Info("3ds FIDO fallback to passcode", "acsTransID", ch.ACSTransID, "step", ch.Step)
	return res, nil
}

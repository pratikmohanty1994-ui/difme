package acs_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/jackc/pgx/v5"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/scheme"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
)

const (
	rpID           = "acs.difme.test"
	acsOrigin      = "https://acs.difme.test"
	merchantOrigin = "https://merchant.example"
)

var b64u = base64.RawURLEncoding.EncodeToString

// softAuth is a software WebAuthn authenticator: a P-256 key, real authenticatorData, clientDataJSON and ES256
// signatures ([WEBAUTHN] §6.1, §6.3.3).
type softAuth struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftAuth(t *testing.T) *softAuth {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softAuth{key: k, id: id}
}

func (s *softAuth) cose() []byte {
	pub, _ := s.key.PublicKey.ECDH()
	raw := pub.Bytes() // 0x04 || X || Y
	b, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve: 1, XCoord: raw[1:33], YCoord: raw[33:]})
	if err != nil {
		panic(err)
	}
	return b
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

func (s *softAuth) authData(rp string, flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(rp))
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, s.count)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID: none
		out = binary.BigEndian.AppendUint16(out, uint16(len(s.id)))
		out = append(out, s.id...)
		out = append(out, s.cose()...)
	}
	return out
}

// attest answers navigator.credentials.create with a "none" attestation.
func (s *softAuth) attest(challenge, origin string) []byte {
	cdj, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin})
	att, _ := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": s.authData(rpID, flagUP|flagUV|flagAT, true)})
	b, _ := json.Marshal(map[string]any{"id": b64u(s.id), "rawId": b64u(s.id), "type": "public-key",
		"response": map[string]string{"clientDataJSON": b64u(cdj), "attestationObject": b64u(att)}})
	return b
}

// assert answers navigator.credentials.get / SPC with client data cd (its counter advanced first).
func (s *softAuth) assert(cd map[string]any) []byte {
	s.count++
	cdj, _ := json.Marshal(cd)
	ad := s.authData(rpID, flagUP|flagUV, false)
	h := sha256.Sum256(cdj)
	d := sha256.Sum256(append(slices.Clone(ad), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, d[:])
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64u(s.id), "rawId": b64u(s.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]string{"clientDataJSON": b64u(cdj), "authenticatorData": b64u(ad), "signature": b64u(sig)}})
	return b
}

func fidoACS(t *testing.T, w *world, creds acs.CredentialStore) *acs.ACS {
	return acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "https://acs.difme.test/3ds/challenge", PayerKey: []byte("test-key-0123456789"),
		Now: func() time.Time { return w.now }, Credentials: creds,
		FIDO: acs.FIDOConfig{RPID: rpID, Origins: []string{acsOrigin, "android:apk-key-hash:test"}, TrustedRequestorRPIDs: []string{"merchant.example"}}},
		w.cmsClient(), w.frm, w.hsm, w.otp, w.oob, w.rreqs)
}

func register(t *testing.T, a *acs.ACS, card string) *softAuth {
	t.Helper()
	ctx := context.Background()
	opts, err := a.FIDORegistrationOptions(ctx, card)
	if err != nil {
		t.Fatal(err)
	}
	pk := opts["publicKey"].(map[string]any)
	s := newSoftAuth(t)
	id, err := a.FIDORegister(ctx, card, opts["registrationToken"].(string), s.attest(pk["challenge"].(string), acsOrigin))
	if err != nil || id != b64u(s.id) {
		t.Fatalf("register: %v %q", err, id)
	}
	return s
}

// webauthnGet is the client data of navigator.credentials.get in the ACS iframe on the merchant page.
func webauthnGet(challenge string) map[string]any {
	return map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": acsOrigin, "crossOrigin": true, "topOrigin": merchantOrigin}
}

// spcGet is SPC client data ([W3C-SPC] CollectedClientPaymentData) for the payment shown.
func spcGet(challenge, origin, value, instrument string) map[string]any {
	return map[string]any{"type": "payment.get", "challenge": challenge, "origin": origin, "crossOrigin": origin != merchantOrigin, "topOrigin": merchantOrigin,
		"payment": map[string]any{"rpId": rpID, "topOrigin": merchantOrigin, "payeeName": "Shop", "total": map[string]string{"currency": "INR", "value": value},
			"instrument": map[string]string{"displayName": instrument, "icon": "x"}}}
}

// startFIDO runs AReq → C (FIDO) → first CReq, returning the ARes and the page's FIDO request.
func startFIDO(t *testing.T, a *acs.ACS) (acs.ARes, *acs.FIDORequest) {
	t.Helper()
	res, err := a.Authenticate(context.Background(), areq(pan, 1000))
	if err != nil || res.TransStatus != "C" || res.ACSRenderingType == nil || res.ACSRenderingType.Template != "05" {
		t.Fatalf("ARes: %v %+v", err, res)
	}
	cres, err := a.Challenge(context.Background(), creqFor(res))
	if err != nil || cres.ACSUIType != "05" || cres.FIDO == nil || len(cres.FIDO.CredentialIDs) == 0 {
		t.Fatalf("FIDO CRes: %v %+v", err, cres)
	}
	return res, cres.FIDO
}

func creqFor(res acs.ARes) acs.CReq {
	return acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID}
}

func (w *world) lastRReq(t *testing.T) acs.RReq {
	t.Helper()
	if len(w.rreqs.got) == 0 {
		t.Fatal("no RReq")
	}
	return w.rreqs.got[len(w.rreqs.got)-1]
}

func TestWebAuthnChallengeSucceedsAndAuthorises(t *testing.T) {
	w := newWorld(t, acs.Alert)
	a := fidoACS(t, w, acs.NewMemoryCredentials())
	s := register(t, a, pan)
	res, req := startFIDO(t, a)
	if !slices.Equal(res.AuthenticationMethod, []string{acs.MethodSPC, acs.MethodWebAuthn}) || !slices.Equal(res.ACSInfoInd, []string{"06", "07"}) ||
		res.AuthenticationType != "02" || w.otp.last != "" {
		t.Fatalf("ARes FIDO fields: %+v otp=%q", res, w.otp.last)
	}
	if !req.SPC || req.Value != "10.00" || req.Currency != "INR" || req.PayeeName != "Shop" || req.RPID != rpID || !strings.HasSuffix(req.Instrument.DisplayName, "0001") {
		t.Fatalf("FIDO request: %+v", req)
	}
	q := creqFor(res)
	q.FIDOAssertion = string(s.assert(webauthnGet(req.Challenge)))
	cres, err := a.Challenge(context.Background(), q)
	if err != nil || cres.TransStatus != "Y" || cres.ChallengeCompletionInd != "Y" {
		t.Fatalf("%v %+v", err, cres)
	}
	rr := w.lastRReq(t)
	if rr.TransStatus != "Y" || rr.ECI != "05" || rr.AuthenticationType != "02" || !slices.Equal(rr.AuthenticationMethod, []string{acs.MethodWebAuthn}) {
		t.Fatalf("RReq: %+v", rr)
	}
	if c, _ := threeds.Decode(rr.AuthenticationValue); c.Result != threeds.ResultChallenge || c.SecondFactor != acs.SecondFactorFIDO {
		t.Fatalf("CAVV: %+v", c)
	}
	if code := authorise(t, w.net, 1000, rr.AuthenticationValue); code != scheme.Approved {
		t.Fatalf("authorisation: %s", code)
	}
	// the same assertion again: the challenge is gone
	if _, err := a.Challenge(context.Background(), q); err == nil {
		t.Fatal("replayed assertion accepted")
	}
}

func TestWebAuthnRejections(t *testing.T) {
	cases := map[string]func(s *softAuth, req *acs.FIDORequest) []byte{
		"wrong challenge": func(s *softAuth, _ *acs.FIDORequest) []byte {
			return s.assert(webauthnGet(b64u([]byte("not-the-challenge-not-the-challenge"))))
		},
		"wrong origin": func(s *softAuth, req *acs.FIDORequest) []byte {
			cd := webauthnGet(req.Challenge)
			cd["origin"] = "https://evil.example"
			return s.assert(cd)
		},
		"bad signature": func(s *softAuth, req *acs.FIDORequest) []byte {
			other := newSoftAuth(t)
			other.id, other.count = s.id, s.count
			return other.assert(webauthnGet(req.Challenge))
		},
		"SPC amount tampered": func(s *softAuth, req *acs.FIDORequest) []byte {
			return s.assert(spcGet(req.Challenge, acsOrigin, "1.00", req.Instrument.DisplayName))
		},
		"SPC payee tampered": func(s *softAuth, req *acs.FIDORequest) []byte {
			cd := spcGet(req.Challenge, acsOrigin, "10.00", req.Instrument.DisplayName)
			cd["payment"].(map[string]any)["payeeName"] = "Other shop"
			return s.assert(cd)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, acs.Alert)
			a := fidoACS(t, w, acs.NewMemoryCredentials())
			s := register(t, a, pan)
			res, req := startFIDO(t, a)
			q := creqFor(res)
			q.FIDOAssertion = string(mk(s, req))
			cres, err := a.Challenge(context.Background(), q)
			if err != nil || cres.TransStatus != "N" {
				t.Fatalf("%v %+v", err, cres)
			}
			if rr := w.lastRReq(t); rr.TransStatus != "N" || rr.TransStatusReason != acs.ReasonAuthFailed || rr.AuthenticationValue != "" {
				t.Fatalf("RReq: %+v", rr)
			}
		})
	}
}

func TestSPCInChallengePageBindsTheTransaction(t *testing.T) {
	w := newWorld(t, acs.Alert)
	a := fidoACS(t, w, acs.NewMemoryCredentials())
	s := register(t, a, pan)
	res, req := startFIDO(t, a)
	q := creqFor(res)
	q.FIDOAssertion = string(s.assert(spcGet(req.Challenge, acsOrigin, "10.00", req.Instrument.DisplayName)))
	if cres, err := a.Challenge(context.Background(), q); err != nil || cres.TransStatus != "Y" {
		t.Fatalf("%v %+v", err, cres)
	}
	if rr := w.lastRReq(t); !slices.Equal(rr.AuthenticationMethod, []string{acs.MethodSPC}) || rr.ECI != "05" {
		t.Fatalf("RReq: %+v", rr)
	}
}

func TestReplayedSignatureCounter(t *testing.T) {
	w := newWorld(t, acs.Alert)
	a := fidoACS(t, w, acs.NewMemoryCredentials())
	s := register(t, a, pan)
	res, req := startFIDO(t, a)
	s.count = 41
	q := creqFor(res)
	q.FIDOAssertion = string(s.assert(webauthnGet(req.Challenge))) // counter 42
	if cres, _ := a.Challenge(context.Background(), q); cres.TransStatus != "Y" {
		t.Fatalf("first: %+v", cres)
	}
	// a cloned authenticator (or replay) presents a counter not above the stored 42, on a fresh, correct challenge
	res, req = startFIDO(t, a)
	s.count = 41
	q = creqFor(res)
	q.FIDOAssertion = string(s.assert(webauthnGet(req.Challenge)))
	cres, err := a.Challenge(context.Background(), q)
	if err != nil || cres.TransStatus != "N" {
		t.Fatalf("stale counter: %v %+v", err, cres)
	}
	if rr := w.lastRReq(t); rr.TransStatusReason != acs.ReasonSecurity {
		t.Fatalf("RReq: %+v", rr)
	}
}

func TestFIDOFallsBackToPasscode(t *testing.T) {
	t.Run("card without credential", func(t *testing.T) {
		w := newWorld(t, acs.Alert)
		a := fidoACS(t, w, acs.NewMemoryCredentials())
		res, _ := a.Authenticate(context.Background(), areq(pan, 1000))
		if res.TransStatus != "C" || res.ACSRenderingType.Template != "01" || w.otp.last == "" || res.AuthenticationMethod != nil || res.ACSInfoInd != nil {
			t.Fatalf("%+v otp=%q", res, w.otp.last)
		}
	})
	t.Run("unknown credential", func(t *testing.T) {
		w := newWorld(t, acs.Alert)
		a := fidoACS(t, w, acs.NewMemoryCredentials())
		register(t, a, pan)
		res, req := startFIDO(t, a)
		q := creqFor(res)
		q.FIDOAssertion = string(newSoftAuth(t).assert(webauthnGet(req.Challenge)))
		cres, err := a.Challenge(context.Background(), q)
		if err != nil || cres.ChallengeCompletionInd != "N" || cres.ACSUIType != "01" || w.otp.last == "" {
			t.Fatalf("fallback: %v %+v", err, cres)
		}
		q = creqFor(res)
		q.ChallengeDataEntry = w.otp.last
		if cres, _ := a.Challenge(context.Background(), q); cres.TransStatus != "Y" {
			t.Fatalf("passcode after fallback: %+v", cres)
		}
		if rr := w.lastRReq(t); rr.AuthenticationMethod != nil || rr.AuthenticationType != "02" {
			t.Fatalf("RReq after fallback: %+v", rr)
		}
	})
}

func TestBrowserPageFIDOAndDecline(t *testing.T) {
	w := newWorld(t, acs.Alert)
	a := fidoACS(t, w, acs.NewMemoryCredentials())
	s := register(t, a, pan)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	post := func(form url.Values) string {
		r, err := http.PostForm(srv.URL+"/3ds/challenge", form)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		return string(b)
	}
	start := func() (acs.ARes, string) {
		q := areq(pan, 1000)
		q.NotificationURL = "https://merchant.example/3ds/notify"
		res, _ := a.Authenticate(context.Background(), q)
		creq, _ := json.Marshal(creqFor(res))
		return res, post(url.Values{"creq": {b64u(creq)}, "threeDSSessionData": {"sess-1"}})
	}
	form := func(res acs.ARes, k, v string) url.Values {
		return url.Values{"acsTransID": {res.ACSTransID}, "threeDSServerTransID": {"srv-1"}, "messageVersion": {"2.3.1"}, "threeDSSessionData": {"sess-1"}, k: {v}}
	}
	res, html := start()
	if !strings.Contains(html, `id="fido" data-o="`) || !strings.Contains(html, "secure-payment-confirmation") || !strings.Contains(html, `name="fidoFallback"`) {
		t.Fatalf("FIDO page: %s", html)
	}
	enc := html[strings.Index(html, `data-o="`)+len(`data-o="`):]
	var req acs.FIDORequest
	if err := json.Unmarshal([]byte(htmlUnescape(enc[:strings.Index(enc, `"`)])), &req); err != nil || req.Challenge == "" {
		t.Fatalf("data-o: %v", err)
	}
	html = post(form(res, "fidoAssertion", string(s.assert(webauthnGet(req.Challenge)))))
	if !strings.Contains(html, `action="https://merchant.example/3ds/notify"`) {
		t.Fatalf("final page: %s", html)
	}
	// the browser declines: passcode page
	res, _ = start()
	html = post(form(res, "fidoFallback", "Y"))
	if !strings.Contains(html, `name="challengeDataEntry"`) || w.otp.last == "" {
		t.Fatalf("fallback page: %s", html)
	}
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&#34;", `"`, "&quot;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#43;", "+", "&#39;", "'").Replace(s)
}

func TestMerchantInitiatedSPC(t *testing.T) {
	setup := func(t *testing.T) (*world, *acs.ACS, *softAuth, acs.ARes) {
		w := newWorld(t, acs.Alert)
		a := fidoACS(t, w, acs.NewMemoryCredentials())
		s := register(t, a, pan)
		q := areq(pan, 1000)
		q.SPCSupport = "Y"
		res, err := a.Authenticate(context.Background(), q)
		if err != nil || res.TransStatus != "S" || res.SPCTransData == nil || len(res.WebAuthnCredList) != 1 || res.ACSURL != "" ||
			res.WebAuthnCredList[0].Credential != b64u(s.id) || res.SPCTransData.Value != "10.00" || res.SPCTransData.PayeeName != "Shop" {
			t.Fatalf("ARes #1: %v %+v", err, res)
		}
		return w, a, s, res
	}
	areq2 := func(res acs.ARes, assertion []byte) acs.AReq {
		q := areq(pan, 1000)
		q.ThreeDSServerTransID = "srv-2"
		q.ReqAuthInfo = &acs.ReqAuthInfo{Method: acs.ReqAuthSPCAssertion, Timestamp: "202611231200", Data: string(assertion)}
		q.PriorAuthInfo = &acs.PriorAuthInfo{Ref: res.ACSTransID, Method: acs.PriorAuthSPC, Timestamp: "202611231200"}
		return q
	}
	t.Run("success, then replay", func(t *testing.T) {
		w, a, s, res := setup(t)
		d := res.SPCTransData
		assertion := s.assert(spcGet(d.Challenge, merchantOrigin, d.Value, d.DisplayName))
		res2, err := a.Authenticate(context.Background(), areq2(res, assertion))
		if err != nil || res2.TransStatus != "Y" || res2.ECI != "05" || !slices.Equal(res2.AuthenticationMethod, []string{acs.MethodSPC}) {
			t.Fatalf("ARes #2: %v %+v", err, res2)
		}
		if code := authorise(t, w.net, 1000, res2.AuthenticationValue); code != scheme.Approved {
			t.Fatalf("authorisation: %s", code)
		}
		// replayed AReq #2: the SPC challenge was consumed, so the ACS challenges with a passcode
		res3, _ := a.Authenticate(context.Background(), areq2(res, assertion))
		if res3.TransStatus != "C" || res3.AuthenticationValue != "" || res3.ACSRenderingType.Template != "01" {
			t.Fatalf("replay: %+v", res3)
		}
	})
	t.Run("amount tampered in client data", func(t *testing.T) {
		_, a, s, res := setup(t)
		d := res.SPCTransData
		res2, _ := a.Authenticate(context.Background(), areq2(res, s.assert(spcGet(d.Challenge, merchantOrigin, "0.10", d.DisplayName))))
		if res2.TransStatus != "N" || res2.TransStatusReason != acs.ReasonAuthFailed {
			t.Fatalf("%+v", res2)
		}
	})
	t.Run("AReq 2 amount differs from AReq 1", func(t *testing.T) {
		_, a, s, res := setup(t)
		d := res.SPCTransData
		q := areq2(res, s.assert(spcGet(d.Challenge, merchantOrigin, d.Value, d.DisplayName)))
		q.PurchaseAmount = "999"
		if res2, _ := a.Authenticate(context.Background(), q); res2.TransStatus != "N" {
			t.Fatalf("%+v", res2)
		}
	})
	t.Run("plain WebAuthn assertion refused", func(t *testing.T) {
		_, a, s, res := setup(t)
		cd := webauthnGet(res.SPCTransData.Challenge)
		if res2, _ := a.Authenticate(context.Background(), areq2(res, s.assert(cd))); res2.TransStatus != "N" {
			t.Fatalf("%+v", res2)
		}
	})
}

func TestRequestorFIDOAuthDataIsAccepted(t *testing.T) {
	w := newWorld(t, acs.NoAlert)
	a := fidoACS(t, w, acs.NewMemoryCredentials())
	q := areq(pan, 1000)
	data, _ := json.Marshal(map[string]any{"rpId": "merchant.example", "authTime": w.now.UTC().Format("2006-01-02T15:04:05Z"),
		"FIDOAuthenticatorReferences": []map[string]any{{"publicKey": "BJDL", "aaguid": "0132d110-bf4e-4208-a403-ab4f5f12efe5", "usedForThisTransaction": true, "up": true, "uv": true}}})
	q.ReqAuthInfo = &acs.ReqAuthInfo{Method: acs.ReqAuthFIDO, Timestamp: "202611231200", Data: string(data)}
	if res, err := a.Authenticate(context.Background(), q); err != nil || res.TransStatus != "Y" {
		t.Fatalf("%v %+v", err, res)
	}
	q.ReqAuthInfo.Data = "not json"
	if res, err := a.Authenticate(context.Background(), q); err != nil || res.TransStatus != "Y" {
		t.Fatalf("malformed FIDO data must not break the flow: %v %+v", err, res)
	}
}

func TestFIDORegistrationOverHTTP(t *testing.T) {
	w := newWorld(t, acs.Alert)
	a := acs.New(acs.Config{FrictionlessLimitMinor: 500_000, PayerKey: []byte("test-key-0123456789"), Now: func() time.Time { return w.now },
		FIDO: acs.FIDOConfig{RPID: rpID, Origins: []string{acsOrigin}}, IssuerAuth: acs.BearerAuth("issuer-token")},
		w.cmsClient(), w.frm, w.hsm, w.otp, w.oob, w.rreqs)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	call := func(method, path, token string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(string(b)))
		if token != "" {
			req.Header.Set("authorization", "Bearer "+token)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	if code, _ := call("POST", "/3ds/fido/registration/options", "", map[string]string{"acctNumber": pan}); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call("POST", "/3ds/oob/x", "wrong", map[string]bool{"approved": true}); code != 401 {
		t.Fatalf("OOB endpoint shares the issuer auth: %d", code)
	}
	code, opts := call("POST", "/3ds/fido/registration/options", "issuer-token", map[string]string{"acctNumber": pan})
	if code != 200 {
		t.Fatalf("options: %d %v", code, opts)
	}
	pk := opts["publicKey"].(map[string]any)
	if pk["rp"].(map[string]any)["id"] != rpID || pk["extensions"].(map[string]any)["payment"].(map[string]any)["isPayment"] != true ||
		strings.Contains(opts["registrationToken"].(string), pan) {
		t.Fatalf("options: %v", opts)
	}
	s := newSoftAuth(t)
	cred := json.RawMessage(s.attest(pk["challenge"].(string), acsOrigin))
	body := map[string]any{"acctNumber": pan, "registrationToken": opts["registrationToken"], "credential": cred}
	if code, out := call("POST", "/3ds/fido/registration", "issuer-token", map[string]any{"acctNumber": twoPAN, "registrationToken": opts["registrationToken"], "credential": cred}); code != 400 {
		t.Fatalf("token for another card: %d %v", code, out)
	}
	if code, out := call("POST", "/3ds/fido/registration", "issuer-token", body); code != 200 || out["credentialId"] != b64u(s.id) {
		t.Fatalf("register: %d %v", code, out)
	}
	if code, _ := call("POST", "/3ds/fido/registration", "issuer-token", body); code != 400 {
		t.Fatalf("second registration of the same credential: %d", code)
	}
	bad := newSoftAuth(t)
	_, opts = call("POST", "/3ds/fido/registration/options", "issuer-token", map[string]string{"acctNumber": pan})
	wrongOrigin := json.RawMessage(bad.attest(opts["publicKey"].(map[string]any)["challenge"].(string), "https://evil.example"))
	if code, _ := call("POST", "/3ds/fido/registration", "issuer-token", map[string]any{"acctNumber": pan, "registrationToken": opts["registrationToken"], "credential": wrongOrigin}); code != 400 {
		t.Fatalf("wrong origin registration: %d", code)
	}
	if code, out := call("DELETE", "/3ds/fido/credentials/"+b64u(s.id), "issuer-token", map[string]string{"acctNumber": pan}); code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if res, _ := a.Authenticate(context.Background(), areq(pan, 1000)); res.ACSRenderingType == nil || res.ACSRenderingType.Template != "01" {
		t.Fatalf("after delete: %+v", res)
	}
}

func credStores(t *testing.T) map[string]func(t *testing.T) acs.CredentialStore {
	return map[string]func(t *testing.T) acs.CredentialStore{
		"memory": func(*testing.T) acs.CredentialStore { return acs.NewMemoryCredentials() },
		"postgres": func(t *testing.T) acs.CredentialStore {
			s := pgStore(t)
			clearCreds(t)
			return s
		},
	}
}

func clearCreds(t *testing.T) {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, pgURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "DELETE FROM acs_fido_credential"); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialStoreContract(t *testing.T) {
	for name, mk := range credStores(t) {
		t.Run(name, func(t *testing.T) {
			s, ctx := mk(t), context.Background()
			c := acs.FIDOCredential{ID: []byte("cred-1"), PublicKey: []byte{1, 2, 3}, SignCount: 7, SPC: true, Created: time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)}
			if err := s.AddCredential(ctx, "card-a", c); err != nil {
				t.Fatal(err)
			}
			if err := s.AddCredential(ctx, "card-b", c); !errors.Is(err, acs.ErrCredentialExists) {
				t.Fatalf("duplicate id on another card: %v", err)
			}
			got, err := s.Credentials(ctx, "card-a")
			if err != nil || len(got) != 1 || string(got[0].ID) != "cred-1" || got[0].SignCount != 7 || !got[0].SPC || string(got[0].PublicKey) != "\x01\x02\x03" {
				t.Fatalf("%v %+v", err, got)
			}
			if got, _ := s.Credentials(ctx, "card-b"); len(got) != 0 {
				t.Fatalf("other card: %+v", got)
			}
			if err := s.UpdateSignCount(ctx, "card-a", c.ID, 6, 9); !errors.Is(err, acs.ErrConflict) {
				t.Fatalf("stale counter CAS: %v", err)
			}
			if err := s.UpdateSignCount(ctx, "card-b", c.ID, 7, 9); !errors.Is(err, acs.ErrNoCredential) {
				t.Fatalf("other card's credential: %v", err)
			}
			if err := s.UpdateSignCount(ctx, "card-a", c.ID, 7, 9); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.Credentials(ctx, "card-a"); got[0].SignCount != 9 {
				t.Fatalf("counter: %+v", got)
			}
			if err := s.DeleteCredential(ctx, "card-b", c.ID); !errors.Is(err, acs.ErrNoCredential) {
				t.Fatalf("delete from other card: %v", err)
			}
			if err := s.DeleteCredential(ctx, "card-a", c.ID); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.Credentials(ctx, "card-a"); len(got) != 0 {
				t.Fatalf("after delete: %+v", got)
			}
		})
	}
}

// With Postgres: credentials registered through the ACS are sealed (no public key, credential id or PAN in clear),
// filed under the card reference, and a FIDO challenge works across them.
func TestPostgresSealedCredentials(t *testing.T) {
	sealer := &xorSealer{}
	store := pgStore(t).Seal(sealer)
	clearCreds(t)
	w := newWorld(t, acs.Alert)
	a := fidoACS(t, w, store)
	s := register(t, a, pan)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, pgURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var ref, doc string
	if err := c.QueryRow(ctx, "SELECT card_ref, doc::text FROM acs_fido_credential").Scan(&ref, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, "card-") || strings.Contains(ref, pan) || !strings.Contains(doc, `"sealed"`) || strings.Contains(doc, "publicKey") ||
		strings.Contains(doc, b64u(s.id)) || strings.Contains(doc, base64.StdEncoding.EncodeToString(s.id)) {
		t.Fatalf("credential row not sealed: %s %s", ref, doc)
	}
	a2 := fidoACS(t, w, store) // another replica
	res, req := startFIDO(t, a2)
	q := creqFor(res)
	q.FIDOAssertion = string(s.assert(webauthnGet(req.Challenge)))
	if cres, err := a2.Challenge(ctx, q); err != nil || cres.TransStatus != "Y" {
		t.Fatalf("%v %+v", err, cres)
	}
}

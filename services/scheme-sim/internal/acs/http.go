package acs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// CMSClient reads cards from card management over HTTP (today the scheme simulator's card API, GET /v1/cards/{pan};
// card-issuer's when it exists, ADR-024).
type CMSClient struct {
	URL  string
	HTTP *http.Client
}

func NewCMSClient(url string) *CMSClient {
	return &CMSClient{URL: url, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

func (c *CMSClient) Card(ctx context.Context, pan string) (Card, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/v1/cards/"+pan, nil)
	if err != nil {
		return Card{}, false, err
	}
	r, err := c.HTTP.Do(req)
	if err != nil {
		return Card{}, false, err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusNotFound {
		return Card{}, false, nil
	}
	if r.StatusCode != http.StatusOK {
		return Card{}, false, fmt.Errorf("CMS: HTTP %d", r.StatusCode)
	}
	var card Card
	err = json.NewDecoder(r.Body).Decode(&struct {
		Expiry   *string   `json:"expiry"`
		Status   *string   `json:"status"`
		Holder   *string   `json:"holder"`
		Channels *[]string `json:"channels"`
		Email    *string   `json:"email"`
		Mobile   *string   `json:"mobile"`
	}{&card.Expiry, &card.Status, &card.Holder, &card.Channels, &card.Email, &card.Mobile})
	return card, err == nil, err
}

// DSClient posts RReqs to the directory server (which relays them to the 3DS Server).
type DSClient struct {
	URL  string
	HTTP *http.Client
}

func NewDSClient(url string) *DSClient {
	return &DSClient{URL: url, HTTP: &http.Client{Timeout: 3 * time.Second}}
}

func (d *DSClient) Send(ctx context.Context, rr RReq) error {
	if d.URL == "" {
		return nil
	}
	b, _ := json.Marshal(rr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	r, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("DS: HTTP %d", r.StatusCode)
	}
	return nil
}

// LogOTP is the development passcode channel: it logs the code with the masked card number. Production delivers
// it through the notification service (SMS / app push) and never logs it.
type LogOTP struct{}

func (LogOTP) Send(_ context.Context, pan string, _ Card, channel, otp string) error {
	slog.Warn("3ds DEV passcode (never in production)", "card", mask(pan), "channel", channel, "otp", otp)
	return nil
}

// SMTPSender delivers passcodes by email (channel email) through an SMTP relay: Mailpit on the development cluster,
// the bank's mail relay in production. Channel sms goes through the same relay to <mobile>@<SMSDomain>, the address
// form of email-to-SMS gateways; on the development cluster Mailpit catches those too, so every passcode can be read
// in one inbox. The message names only the card's last four digits.
type SMTPSender struct {
	Addr      string // host:port
	From      string
	SMSDomain string
}

func (s SMTPSender) Send(_ context.Context, pan string, card Card, channel, otp string) error {
	var to, subject string
	switch channel {
	case "email":
		to, subject = card.Email, "Your DIFME card passcode"
	case "sms":
		if card.Mobile != "" {
			to, subject = card.Mobile+"@"+s.SMSDomain, "SMS"
		}
	default:
		return fmt.Errorf("passcode channel %q not deliverable by SMTP", channel)
	}
	if to == "" || strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("card has no %s address for passcodes", channel)
	}
	body := fmt.Sprintf("Your DIFME card ending %s: passcode %s for your online purchase. Never share it; DIFME will never ask for it.", pan[len(pan)-4:], otp)
	msg := "From: " + s.From + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n"
	return smtp.SendMail(s.Addr, nil, s.From, []string{to}, []byte(msg))
}

// LogOOB is the development app-push channel: it logs the request; approve it with POST /3ds/oob/{acsTransID}.
type LogOOB struct{}

func (LogOOB) Notify(_ context.Context, pan, acsTransID, merchant string, amountMinor int64, currency string) error {
	slog.Warn("3ds DEV app push (never in production)", "card", mask(pan), "acsTransID", acsTransID, "merchant", merchant, "amount", amountMinor, "currency", currency)
	return nil
}

func mask(pan string) string { return pan[:6] + "******" + pan[len(pan)-4:] }

// Handler serves POST /3ds/areq, POST /3ds/creq (app, JSON), POST /3ds/challenge (browser, HTML),
// POST /3ds/oob/{acsTransID} (DIFME app's answer: {"approved":true}), GET /healthz, and the issuer app's FIDO
// credential registration (fido.go):
//
//	POST   /3ds/fido/registration/options  {"acctNumber"}  → {"registrationToken", "publicKey": creation options}
//	POST   /3ds/fido/registration          {"acctNumber", "registrationToken", "credential": PublicKeyCredential JSON}
//	                                       → {"credentialId"}
//	DELETE /3ds/fido/credentials/{id}      {"acctNumber"}
//
// The out-of-band and FIDO registration endpoints are issuer/cardholder endpoints: Config.IssuerAuth (when set) and
// the mesh policy guard them alike.
func (a *ACS) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /3ds/areq", func(w http.ResponseWriter, r *http.Request) {
		var q AReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": "AReq JSON required"})
			return
		}
		res, err := a.Authenticate(r.Context(), q)
		reply(w, res, err)
	})
	mux.HandleFunc("POST /3ds/creq", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("content-type"), "application/jose") { // app channel: JWE in, JWE out
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			out, err := a.AppChallenge(r.Context(), strings.TrimSpace(string(b)))
			if err != nil {
				reply(w, nil, err)
				return
			}
			w.Header().Set("content-type", "application/jose; charset=UTF-8")
			_, _ = w.Write([]byte(out))
			return
		}
		var q CReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
			writeJSON(w, 400, map[string]string{"error": "CReq JSON required"})
			return
		}
		res, err := a.Challenge(r.Context(), q)
		reply(w, res, err)
	})
	mux.HandleFunc("POST /3ds/oob/{id}", a.issuer(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Approved bool `json:"approved"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "{\"approved\": bool} required"})
			return
		}
		reply(w, map[string]string{"status": "recorded"}, a.OOBResult(r.Context(), r.PathValue("id"), in.Approved))
	}))
	type fidoIn struct {
		AcctNumber        string          `json:"acctNumber"`
		RegistrationToken string          `json:"registrationToken"`
		Credential        json.RawMessage `json:"credential"`
	}
	readFIDO := func(w http.ResponseWriter, r *http.Request) (fidoIn, bool) {
		var in fidoIn
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in.AcctNumber == "" {
			writeJSON(w, 400, map[string]string{"error": "JSON with acctNumber required"})
			return in, false
		}
		return in, true
	}
	mux.HandleFunc("POST /3ds/fido/registration/options", a.issuer(func(w http.ResponseWriter, r *http.Request) {
		if in, ok := readFIDO(w, r); ok {
			res, err := a.FIDORegistrationOptions(r.Context(), in.AcctNumber)
			reply(w, res, err)
		}
	}))
	mux.HandleFunc("POST /3ds/fido/registration", a.issuer(func(w http.ResponseWriter, r *http.Request) {
		if in, ok := readFIDO(w, r); ok {
			id, err := a.FIDORegister(r.Context(), in.AcctNumber, in.RegistrationToken, in.Credential)
			reply(w, map[string]string{"credentialId": id}, err)
		}
	}))
	mux.HandleFunc("DELETE /3ds/fido/credentials/{id}", a.issuer(func(w http.ResponseWriter, r *http.Request) {
		if in, ok := readFIDO(w, r); ok {
			reply(w, map[string]string{"status": "deleted"}, a.FIDODeregister(r.Context(), in.AcctNumber, r.PathValue("id")))
		}
	}))
	mux.HandleFunc("POST /3ds/challenge", a.browserChallenge)
	mux.HandleFunc("POST /3ds/method", a.methodHandler)
	mux.HandleFunc("POST /3ds/method/collect", a.methodCollect)
	return mux
}

// issuer guards an issuer/cardholder endpoint with Config.IssuerAuth (nil: mesh policy only).
func (a *ACS) issuer(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.IssuerAuth != nil && !a.cfg.IssuerAuth(r) {
			writeJSON(w, 401, map[string]string{"error": "unauthorised"})
			return
		}
		h(w, r)
	}
}

// BearerAuth accepts requests carrying "Authorization: Bearer <token>" (constant-time compare); for Config.IssuerAuth
// (ACS_ISSUER_TOKEN) in addition to the mesh's mTLS identity.
func BearerAuth(token string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		got, ok := strings.CutPrefix(r.Header.Get("authorization"), "Bearer ")
		return ok && token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	}
}

func reply(w http.ResponseWriter, res any, err error) {
	switch {
	case errors.Is(err, ErrBadRequest):
		writeJSON(w, 400, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, 500, map[string]string{"error": "internal error"})
	default:
		writeJSON(w, 200, res)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// HSMSigner signs acsSignedContent in the security module (key "acs-sign"; its certificate from /v1/certs/acs-sign).
func HSMSigner(hsmURL string) (*Signer, error) {
	return HSMSignerWithChain(hsmURL, nil)
}

// HSMSignerWithChain signs in the security module (key "acs-sign") but presents chain (leaf first; e.g. the
// scheme-issued ACS certificate chain from ACS_SIGNING_CERT_CHAIN) in x5c. The leaf's public key must be the
// security module's acs-sign key, and each certificate must be signed by the next. A nil chain uses the security
// module's own certificate.
func HSMSignerWithChain(hsmURL string, chain []*x509.Certificate) (*Signer, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	r, err := c.Get(hsmURL + "/v1/certs/acs-sign")
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out struct {
		X5C string `json:"x5c"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 {
		return nil, fmt.Errorf("security module certificate: HTTP %d", r.StatusCode)
	}
	der, err := base64.StdEncoding.DecodeString(out.X5C)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		chain = []*x509.Certificate{cert}
	} else if err := checkChain(chain, cert.PublicKey); err != nil {
		return nil, err
	}
	return &Signer{Chain: chain, Remote: func(in []byte) ([]byte, error) {
		v, err := hsmCall(c, hsmURL+"/v1/sign/ps256", map[string]string{"key": "acs-sign", "data": hex.EncodeToString(in)}, "signature")
		if err != nil {
			return nil, err
		}
		return hex.DecodeString(v)
	}}, nil
}

// LoadCertChain reads a PEM file of certificates, leaf first (ACS_SIGNING_CERT_CHAIN). Private keys are refused:
// the signing key stays in the security module.
func LoadCertChain(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: unexpected PEM block %q (certificates only; the key stays in the security module)", path, blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return chain, nil
}

func checkChain(chain []*x509.Certificate, key any) error {
	pub, ok := key.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(chain[0].PublicKey) {
		return errors.New("ACS signing certificate: leaf public key is not the security module's acs-sign key")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("ACS signing certificate chain: certificate %d not signed by %d: %w", i, i+1, err)
		}
	}
	return nil
}

// HSMMAC computes HMAC-SHA-256 with the security module's "acs-hmac" key.
func HSMMAC(hsmURL string) func(ctx context.Context, data []byte) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	return func(_ context.Context, data []byte) ([]byte, error) {
		v, err := hsmCall(c, hsmURL+"/v1/hmac", map[string]string{"key": "acs-hmac", "data": hex.EncodeToString(data)}, "mac")
		if err != nil {
			return nil, err
		}
		return hex.DecodeString(v)
	}
}

func hsmCall(c *http.Client, url string, in map[string]string, field string) (string, error) {
	b, _ := json.Marshal(in)
	r, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 || out[field] == "" {
		return "", fmt.Errorf("security module %s: HTTP %d", url, r.StatusCode)
	}
	return out[field], nil
}

// HSMSealer seals ACS challenge documents with the security module's card-vault key (AES-GCM, aad = acsTransID).
type HSMSealer struct{ URL string }

func (h HSMSealer) Seal(_ context.Context, id string, plain []byte) (string, error) {
	return hsmCall(&http.Client{Timeout: 3 * time.Second}, h.URL+"/v1/data/encrypt",
		map[string]string{"key": "card-vault", "data": hex.EncodeToString(plain), "aad": hex.EncodeToString([]byte(id))}, "ciphertext")
}

func (h HSMSealer) Open(_ context.Context, id, sealed string) ([]byte, error) {
	v, err := hsmCall(&http.Client{Timeout: 3 * time.Second}, h.URL+"/v1/data/decrypt",
		map[string]string{"key": "card-vault", "ciphertext": sealed, "aad": hex.EncodeToString([]byte(id))}, "data")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(v)
}

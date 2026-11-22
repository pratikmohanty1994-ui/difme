// Package ntadapter is the network tokenization service Hyperswitch calls (ADR-024): Hyperswitch's
// network_tokenization_service contract on top of the scheme simulator's token service (TSP, internal/tokens).
//
//	POST <generate_token_url>  ApiPayload{cardData: JWE(card), orderData, keyId}  ->  {payload: JWE(token details)}
//	POST <fetch_token_url>     {card_reference, customer_id}  ->  token + cryptogram (TAVV from the security module)
//	POST <delete_token_url>    {card_reference, customer_id}  ->  {status: SUCCESS}
//	POST <check_token_status_url> {card_reference, customer_id} -> {payload: {token_status, token_expiry_*}}
//
// Card data arrives as JWE compact (RSA-OAEP-256 + A128GCM) encrypted to this service's key; the generate response is
// a JWE encrypted to Hyperswitch's public key. Authorization header = the shared API key. The card number is never
// logged or returned; Hyperswitch keeps only the token and the card reference.
package ntadapter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/tokens"
)

var b64 = base64.RawURLEncoding

// Adapter serves Hyperswitch's network tokenization calls.
type Adapter struct {
	Vault     *tokens.Vault
	Requestor string // token requestor id for Hyperswitch (tokens are bound to it)
	APIKey    string // shared key Hyperswitch sends in Authorization
	// Unwrap decrypts a JWE's RSA-OAEP-256 content-key: in the security module (key nts-jwe), so the adapter holds no
	// private key (ADR-026). Hyperswitch's public_key setting is that key's public half (hsm GET /v1/certs/nts-jwe).
	Unwrap      func(encryptedKey []byte) ([]byte, error)
	Hyperswitch *rsa.PublicKey // encrypts generate responses (Hyperswitch's private_key setting is its private half)
	KeyID       string
	mu          sync.Mutex
	refs        map[string]ref // card reference -> token
}

type ref struct {
	token, customer, expMonth, expYear string
}

func New(v *tokens.Vault, requestor, apiKey, keyID string, unwrap func([]byte) ([]byte, error), hs *rsa.PublicKey) *Adapter {
	return &Adapter{Vault: v, Requestor: requestor, APIKey: apiKey, KeyID: keyID, Unwrap: unwrap, Hyperswitch: hs, refs: map[string]ref{}}
}

// LocalUnwrap unwraps with a local private key (tests only).
func LocalUnwrap(priv *rsa.PrivateKey) func([]byte) ([]byte, error) {
	return func(ek []byte) ([]byte, error) { return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ek, nil) }
}

// DecryptJWE opens a compact JWE with alg RSA-OAEP-256 and enc A128GCM/A256GCM.
func DecryptJWE(priv *rsa.PrivateKey, compact string) ([]byte, error) {
	return OpenJWE(LocalUnwrap(priv), compact)
}

// OpenJWE opens a compact JWE, unwrapping the content key with unwrap.
func OpenJWE(unwrap func([]byte) ([]byte, error), compact string) ([]byte, error) {
	p := strings.Split(compact, ".")
	if len(p) != 5 {
		return nil, errors.New("JWE compact form required")
	}
	hb, err := b64.DecodeString(p[0])
	if err != nil {
		return nil, err
	}
	var h struct{ Alg, Enc string }
	if json.Unmarshal(hb, &h) != nil || h.Alg != "RSA-OAEP-256" || (h.Enc != "A128GCM" && h.Enc != "A256GCM") {
		return nil, fmt.Errorf("JWE algorithms %s/%s not supported", h.Alg, h.Enc)
	}
	ek, err1 := b64.DecodeString(p[1])
	iv, err2 := b64.DecodeString(p[2])
	ct, err3 := b64.DecodeString(p[3])
	tag, err4 := b64.DecodeString(p[4])
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, err
	}
	cek, err := unwrap(ek)
	if err != nil {
		return nil, errors.New("JWE key unwrap failed")
	}
	blk, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil || len(iv) != g.NonceSize() {
		return nil, errors.New("JWE: bad GCM parameters")
	}
	return g.Open(nil, iv, append(ct, tag...), []byte(p[0]))
}

// EncryptJWE seals plaintext for pub (RSA-OAEP-256 + A128GCM, compact).
func EncryptJWE(pub *rsa.PublicKey, plaintext []byte, kid string) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RSA-OAEP-256", "enc": "A128GCM", "kid": kid})
	h := b64.EncodeToString(hdr)
	cek, iv := make([]byte, 16), make([]byte, 12)
	_, _ = rand.Read(cek)
	_, _ = rand.Read(iv)
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return "", err
	}
	blk, _ := aes.NewCipher(cek)
	g, _ := cipher.NewGCM(blk)
	out := g.Seal(nil, iv, plaintext, []byte(h))
	return h + "." + b64.EncodeToString(ek) + "." + b64.EncodeToString(iv) + "." + b64.EncodeToString(out[:len(out)-16]) + "." +
		b64.EncodeToString(out[len(out)-16:]), nil
}

func (a *Adapter) authorised(r *http.Request) bool {
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return a.APIKey != "" && subtle.ConstantTimeCompare([]byte(got), []byte(a.APIKey)) == 1
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error_message": msg, "error_info": map[string]string{"code": code, "developer_message": msg}})
}

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func network(pan string) string {
	switch {
	case strings.HasPrefix(pan, "4"):
		return "Visa"
	case strings.HasPrefix(pan, "5") || strings.HasPrefix(pan, "2"):
		return "Mastercard"
	case strings.HasPrefix(pan, "34") || strings.HasPrefix(pan, "37"):
		return "AmericanExpress"
	}
	return "Visa"
}

// Handler mounts the four calls under prefix (e.g. /nts).
func (a *Adapter) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+prefix+"/generate", a.generate)
	mux.HandleFunc("POST "+prefix+"/token", a.fetch)
	mux.HandleFunc("POST "+prefix+"/delete", a.del)
	mux.HandleFunc("POST "+prefix+"/status", a.status)
	return mux
}

type refReq struct {
	CardReference string `json:"card_reference"`
	CustomerID    string `json:"customer_id"`
}

func (a *Adapter) lookup(w http.ResponseWriter, r *http.Request) (refReq, ref, bool) {
	var q refReq
	if !a.authorised(r) {
		fail(w, 401, "UNAUTHORIZED", "invalid API key")
		return q, ref{}, false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
		fail(w, 400, "BAD_REQUEST", "JSON body required")
		return q, ref{}, false
	}
	a.mu.Lock()
	t, found := a.refs[q.CardReference]
	a.mu.Unlock()
	if !found || t.customer != q.CustomerID {
		fail(w, 404, "NOT_FOUND", "unknown card reference")
		return q, ref{}, false
	}
	return q, t, true
}

func (a *Adapter) generate(w http.ResponseWriter, r *http.Request) {
	if !a.authorised(r) {
		fail(w, 401, "UNAUTHORIZED", "invalid API key")
		return
	}
	var q struct {
		Service    string `json:"service"`
		CardData   string `json:"cardData"`
		ShouldSend bool   `json:"shouldSendToken"`
		KeyID      string `json:"keyId"`
		OrderData  struct {
			ConsentID  string `json:"consentId"`
			CustomerID string `json:"customerId"`
		} `json:"orderData"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil || q.CardData == "" {
		fail(w, 400, "BAD_REQUEST", "ApiPayload with cardData required")
		return
	}
	pt, err := OpenJWE(a.Unwrap, q.CardData)
	if err != nil {
		fail(w, 400, "DECRYPTION_FAILED", "card data could not be decrypted")
		return
	}
	var card struct {
		CardNumber string `json:"cardNumber"`
		ExpMonth   string `json:"expMonth"`
		ExpYear    string `json:"expYear"`
	}
	if json.Unmarshal(pt, &card) != nil || len(card.CardNumber) < 13 {
		fail(w, 400, "BAD_CARD", "card data incomplete")
		return
	}
	tok, err := a.Vault.Provision(card.CardNumber, a.Requestor)
	if err != nil {
		fail(w, 422, "NOT_ELIGIBLE", "card not eligible for tokenization")
		return
	}
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	cardRef := hex.EncodeToString(rb)
	year := card.ExpYear
	if len(year) == 2 {
		year = "20" + year
	}
	a.mu.Lock()
	a.refs[cardRef] = ref{token: tok.Number, customer: q.OrderData.CustomerID, expMonth: card.ExpMonth, expYear: year}
	a.mu.Unlock()
	fp := sha256.Sum256([]byte("fp|" + card.CardNumber))
	payload, _ := json.Marshal(map[string]any{
		"cardBrand": network(card.CardNumber), "cardFingerprint": hex.EncodeToString(fp[:16]), "cardReference": cardRef,
		"correlationId": q.OrderData.ConsentID, "customerId": q.OrderData.CustomerID, "par": "PAR" + hex.EncodeToString(fp[16:28]),
		"token": tok.Number, "tokenExpiryMonth": card.ExpMonth, "tokenExpiryYear": year, "tokenIsin": tok.Number[:8],
		"tokenLastFour": tok.Number[len(tok.Number)-4:], "tokenStatus": "ACTIVE"})
	jwe, err := EncryptJWE(a.Hyperswitch, payload, a.KeyID)
	if err != nil {
		fail(w, 500, "ENCRYPTION_FAILED", "response encryption failed")
		return
	}
	ok(w, map[string]string{"payload": jwe})
}

func (a *Adapter) fetch(w http.ResponseWriter, r *http.Request) {
	_, t, found := a.lookup(w, r)
	if !found {
		return
	}
	cg, err := a.Vault.Cryptogram(t.token, a.Requestor, 0)
	if err != nil {
		fail(w, 409, "TOKEN_INACTIVE", err.Error())
		return
	}
	ok(w, map[string]any{
		"authentication_details": map[string]string{"cryptogram": strings.TrimPrefix(cg, "TAVV:"), "token": t.token},
		"network":                network(t.token), "token_details": map[string]string{"exp_month": t.expMonth, "exp_year": t.expYear},
		"eci": "07"})
}

func (a *Adapter) del(w http.ResponseWriter, r *http.Request) {
	q, t, found := a.lookup(w, r)
	if !found {
		return
	}
	_ = a.Vault.SetStatus(t.token, "DELETED")
	a.mu.Lock()
	delete(a.refs, q.CardReference)
	a.mu.Unlock()
	ok(w, map[string]string{"status": "SUCCESS"})
}

func (a *Adapter) status(w http.ResponseWriter, r *http.Request) {
	_, t, found := a.lookup(w, r)
	if !found {
		return
	}
	ok(w, map[string]any{"payload": map[string]any{"token_status": "ACTIVE", "token_expiry_month": t.expMonth, "token_expiry_year": t.expYear,
		"token_last_four": t.token[len(t.token)-4:]}})
}

// HSMUnwrap unwraps JWE content keys with the security module's RSA-OAEP key (label nts-jwe).
func HSMUnwrap(hsmURL, label string) func([]byte) ([]byte, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	return func(ek []byte) ([]byte, error) {
		b, _ := json.Marshal(map[string]string{"key": label, "data": hex.EncodeToString(ek)})
		r, err := c.Post(hsmURL+"/v1/rsa/decrypt", "application/json", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		var out map[string]string
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 {
			return nil, fmt.Errorf("security module unwrap: HTTP %d", r.StatusCode)
		}
		return hex.DecodeString(out["data"])
	}
}

package ntadapter

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds/threedstest"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/tokens"
)

func keys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := rsa.GenerateKey(rand.Reader, 2048)
	return a, h
}

var adapterKey *rsa.PrivateKey

func setup(t *testing.T) (*Adapter, *httptest.Server, *rsa.PrivateKey) {
	ad, hs := keys(t)
	v := tokens.New()
	v.HSM = threedstest.New() // TAVV cryptograms as with the security module
	a := New(v, "HYPERSWITCH", "nts-key", "nts-1", LocalUnwrap(ad), &hs.PublicKey)
	adapterKey = ad
	srv := httptest.NewServer(a.Handler("/nts"))
	t.Cleanup(srv.Close)
	return a, srv, hs
}

func post(t *testing.T, url, key string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Authorization", key)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

const card = `{"cardNumber":"4375510000000001","expMonth":"12","expYear":"30","cardSecurityCode":"123"}`

func TestTokenLifecycleForHyperswitch(t *testing.T) {
	a, srv, hs := setup(t)
	jweCard, err := EncryptJWE(&adapterKey.PublicKey, []byte(card), "hs-key-1")
	if err != nil {
		t.Fatal(err)
	}
	gen := map[string]any{"service": "NETWORK_TOKEN", "cardData": jweCard, "shouldSendToken": true, "keyId": "nts-1",
		"orderData": map[string]string{"consentId": "c-1", "customerId": "cus_1"}}
	if code, _ := post(t, srv.URL+"/nts/generate", "wrong", gen); code != 401 {
		t.Fatalf("bad API key: %d", code)
	}
	code, out := post(t, srv.URL+"/nts/generate", "nts-key", gen)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	pt, err := DecryptJWE(hs, out["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(pt, &p)
	tok, ref := p["token"].(string), p["cardReference"].(string)
	if !tokens.IsToken(tok) || p["cardBrand"] != "Visa" || p["tokenExpiryYear"] != "2030" || strings.Contains(string(pt), "4375510000000001") {
		t.Fatalf("payload %s", pt)
	}
	q := map[string]string{"card_reference": ref, "customer_id": "cus_1"}
	if code, _ := post(t, srv.URL+"/nts/token", "nts-key", map[string]string{"card_reference": ref, "customer_id": "cus_2"}); code != 404 {
		t.Errorf("another customer's reference: %d", code)
	}
	code, tr := post(t, srv.URL+"/nts/token", "nts-key", q)
	ad := tr["authentication_details"].(map[string]any)
	if code != 200 || ad["token"] != tok || tr["eci"] != "07" {
		t.Fatalf("%d %v", code, tr)
	}
	// the cryptogram is a TAVV the network accepts for this token and requestor
	if pan, err := a.Vault.Detokenize(tok, "HYPERSWITCH", 0, "TAVV:"+ad["cryptogram"].(string)); err != nil || pan != "4375510000000001" {
		t.Fatalf("TAVV at the network: %v %s", err, pan)
	}
	if c, _ := threeds.Decode(ad["cryptogram"].(string)); c.Result != threeds.ResultToken {
		t.Fatalf("cryptogram layout %+v", c)
	}
	if code, st := post(t, srv.URL+"/nts/status", "nts-key", q); code != 200 || st["payload"].(map[string]any)["token_status"] != "ACTIVE" {
		t.Fatalf("status %d %v", code, st)
	}
	if code, d := post(t, srv.URL+"/nts/delete", "nts-key", q); code != 200 || d["status"] != "SUCCESS" {
		t.Fatalf("delete %d %v", code, d)
	}
	if code, _ := post(t, srv.URL+"/nts/token", "nts-key", q); code != 404 {
		t.Errorf("deleted token still served: %d", code)
	}
	if code, _ := post(t, srv.URL+"/nts/generate", "nts-key", map[string]any{"cardData": "not-a-jwe"}); code != 400 {
		t.Errorf("garbage card data: %d", code)
	}
}

// Against an independent JOSE implementation (jwcrypto) standing in for Hyperswitch.
func TestJWEInteropWithJwcrypto(t *testing.T) {
	if exec.Command("python3", "-c", "import jwcrypto").Run() != nil {
		t.Skip("python3 with jwcrypto not installed")
	}
	_, srv, hs := setup(t)
	dir := t.TempDir()
	pemFile := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, pem.EncodeToMemory(block), 0o600)
		return p
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&adapterKey.PublicKey)
	pub := pemFile("adapter.pub", &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privDER, _ := x509.MarshalPKCS8PrivateKey(hs)
	priv := pemFile("hs.key", &pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	py := func(args ...string) string {
		out, err := exec.Command("python3", append([]string{"testdata/hyperswitch.py"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	jweCard := py("encrypt", pub, card)
	code, out := post(t, srv.URL+"/nts/generate", "nts-key", map[string]any{"service": "NETWORK_TOKEN", "cardData": jweCard, "keyId": "nts-1",
		"orderData": map[string]string{"consentId": "c-2", "customerId": "cus_9"}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(py("decrypt", priv, out["payload"].(string))), &p); err != nil || !tokens.IsToken(p["token"].(string)) {
		t.Fatalf("jwcrypto could not read the response: %v %v", err, p)
	}
}

func TestPublicKeyFromSecurityModule(t *testing.T) {
	a, srv, _ := setup(t)
	der, _ := x509.MarshalPKIXPublicKey(&adapterKey.PublicKey)
	hsm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certs/nts-jwe" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"x5c": base64.StdEncoding.EncodeToString(der)})
	}))
	defer hsm.Close()
	a.PublicKey = HSMPublicKey(hsm.URL, "nts-jwe")
	r, err := http.Get(srv.URL + "/nts/public-key")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	blk, _ := pem.Decode(body)
	if r.StatusCode != 200 || blk == nil || blk.Type != "PUBLIC KEY" {
		t.Fatalf("HTTP %d %q", r.StatusCode, body)
	}
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil || !pk.(*rsa.PublicKey).Equal(&adapterKey.PublicKey) {
		t.Fatalf("public key mismatch: %v", err)
	}
	a.PublicKey = HSMPublicKey(hsm.URL, "missing")
	if r, _ := http.Get(srv.URL + "/nts/public-key"); r.StatusCode != 503 {
		t.Fatalf("missing key: HTTP %d", r.StatusCode)
	}
}

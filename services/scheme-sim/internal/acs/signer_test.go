package acs_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
)

func testCert(t *testing.T, cn string, pub *rsa.PublicKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, ca bool) *x509.Certificate {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: ca}
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// fakeSigningHSM is the security module's acs-sign key (test key generated here): certificate and PS256 signing.
func fakeSigningHSM(t *testing.T, k *rsa.PrivateKey) string {
	self := testCert(t, "hsm acs-sign", &k.PublicKey, nil, k, false)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/certs/acs-sign", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"x5c": base64.StdEncoding.EncodeToString(self.Raw)})
	})
	mux.HandleFunc("POST /v1/sign/ps256", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		data, _ := hex.DecodeString(in["data"])
		d := sha256.Sum256(data)
		sig, _ := rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": hex.EncodeToString(sig)})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s.URL
}

func writePEM(t *testing.T, blocks ...*pem.Block) string {
	p := filepath.Join(t.TempDir(), "chain.pem")
	var b []byte
	for _, blk := range blocks {
		b = append(b, pem.EncodeToMemory(blk)...)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ACS_SIGNING_CERT_CHAIN: the scheme-issued chain from a file goes into x5c, the signature still comes from the
// security module.
func TestSigningCertificateChainFromFile(t *testing.T) {
	hsmKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	hsmURL := fakeSigningHSM(t, hsmKey)
	ca := testCert(t, "Test scheme ACS CA", &caKey.PublicKey, nil, caKey, true)
	leaf := testCert(t, "DIFME ACS", &hsmKey.PublicKey, ca, caKey, false)
	path := writePEM(t, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})

	chain, err := acs.LoadCertChain(path)
	if err != nil || len(chain) != 2 {
		t.Fatalf("%v %d", err, len(chain))
	}
	signer, err := acs.HSMSignerWithChain(hsmURL, chain)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Key != nil {
		t.Fatal("the ACS must not hold the signing key")
	}
	_, jws, err := acs.NewAppSession(*sdkKey(t), "REF", "https://acs.example/3ds/creq", signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	_ = json.Unmarshal(hb, &hdr)
	if hdr.Alg != "PS256" || len(hdr.X5C) != 2 || hdr.X5C[0] != base64.StdEncoding.EncodeToString(leaf.Raw) || hdr.X5C[1] != base64.StdEncoding.EncodeToString(ca.Raw) {
		t.Fatalf("x5c: %+v", hdr)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatalf("acsSignedContent does not verify with the file's leaf: %v", err)
	}

	// without a chain: the security module's own certificate (existing behaviour)
	if s, err := acs.HSMSigner(hsmURL); err != nil || len(s.Chain) != 1 || !s.Chain[0].PublicKey.(*rsa.PublicKey).Equal(&hsmKey.PublicKey) {
		t.Fatalf("HSMSigner: %v", err)
	}
	// a leaf for another key, a broken chain, a private key in the file: refused
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	other := testCert(t, "not ours", &otherKey.PublicKey, ca, caKey, false)
	if _, err := acs.HSMSignerWithChain(hsmURL, []*x509.Certificate{other, ca}); err == nil {
		t.Error("leaf with a foreign key accepted")
	}
	stranger := testCert(t, "other CA", &otherKey.PublicKey, nil, otherKey, true)
	if _, err := acs.HSMSignerWithChain(hsmURL, []*x509.Certificate{leaf, stranger}); err == nil {
		t.Error("chain not signed by its issuer accepted")
	}
	keyPath := writePEM(t, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	if _, err := acs.LoadCertChain(keyPath); err == nil {
		t.Error("PEM with a private key accepted")
	}
	if _, err := acs.LoadCertChain(writePEM(t)); err == nil {
		t.Error("empty PEM accepted")
	}
}

package acs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/ca"
)

// One fake security module holding both the ACS's acs-sign key and the scheme's CA key (as the real one does, each
// reachable only by its own caller); the real scheme CA issues; the ACS signer accepts the chain.
func TestTheACSPresentsASchemeIssuedChainForItsOwnKey(t *testing.T) {
	acsKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	acsSelf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "DIFME acs-sign (dev)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	acsDER, _ := x509.CreateCertificate(rand.Reader, acsSelf, acsSelf, &acsKey.PublicKey, acsKey)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DIFME Card Scheme Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	reply := func(w http.ResponseWriter, m map[string]string) { _ = json.NewEncoder(w).Encode(m) }
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certs/acs-sign", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]string{"x5c": base64.StdEncoding.EncodeToString(acsDER)})
	})
	mux.HandleFunc("/v1/certs/scheme-ca", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]string{"x5c": base64.StdEncoding.EncodeToString(rootDER)})
	})
	mux.HandleFunc("/v1/csr/acs-sign", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: in["cn"]}}, acsKey)
		reply(w, map[string]string{"csr": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/v1/ca/scheme-ca/sign-digest", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		d, _ := hex.DecodeString(in["digest"])
		sig, _ := rsa.SignPKCS1v15(nil, caKey, crypto.SHA256, d)
		reply(w, map[string]string{"signature": hex.EncodeToString(sig)})
	})
	hsm := httptest.NewServer(mux)
	defer hsm.Close()
	iss, err := ca.New(hsm.URL, "scheme-ca")
	if err != nil {
		t.Fatal(err)
	}
	scheme := httptest.NewServer(iss.Handler())
	defer scheme.Close()

	chain, err := SchemeIssuedChain(hsm.URL, scheme.URL, "DIFME ACS")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].Subject.CommonName != "DIFME ACS" || chain[1].Subject.CommonName != "DIFME Card Scheme Root CA" {
		t.Fatalf("unexpected chain %v", chain)
	}
	s, err := HSMSignerWithChain(hsm.URL, chain) // checks: leaf key = the module's acs-sign key, each cert signed by the next
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Chain) != 2 {
		t.Fatal("signer does not present the scheme-issued chain")
	}
}

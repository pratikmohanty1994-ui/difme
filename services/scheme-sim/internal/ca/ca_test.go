package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
)

// fakeHSM holds the CA key (as the security module does) and answers /v1/certs/scheme-ca and the sign-digest call.
func fakeHSM(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DIFME Card Scheme Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certs/scheme-ca", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"x5c": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/v1/ca/scheme-ca/sign-digest", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		d, _ := hex.DecodeString(in["digest"])
		sig, err := rsa.SignPKCS1v15(nil, k, crypto.SHA256, d)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": hex.EncodeToString(sig)})
	})
	return httptest.NewServer(mux), k
}

func csrFor(t *testing.T, k *rsa.PrivateKey, cn string) []byte {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIssuesTheACSSigningCertificateChainedToTheSchemeRoot(t *testing.T) {
	h, _ := fakeHSM(t)
	defer h.Close()
	iss, err := New(h.URL, "scheme-ca")
	if err != nil {
		t.Fatal(err)
	}
	acsKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()
	body, _ := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csrFor(t, acsKey, "DIFME ACS"))})
	r, err := http.Post(srv.URL+"/ca/acs-signing", "application/json", bytes.NewReader(body))
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("issue: %v %v", err, r.StatusCode)
	}
	var out struct{ Chain []string }
	_ = json.NewDecoder(r.Body).Decode(&out)
	if len(out.Chain) != 2 {
		t.Fatalf("chain length %d", len(out.Chain))
	}
	var chain []*x509.Certificate
	for _, c := range out.Chain {
		der, _ := base64.StdEncoding.DecodeString(c)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	if !leaf.PublicKey.(*rsa.PublicKey).Equal(&acsKey.PublicKey) || leaf.Subject.CommonName != "DIFME ACS" {
		t.Fatal("leaf does not carry the requester's key and name")
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[1])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not verify to the scheme root: %v", err)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.IsCA {
		t.Fatal("leaf must be a signing certificate, not a CA")
	}
	// a signature by the ACS key verifies with the issued certificate
	dig := sha256.Sum256([]byte("acsSignedContent"))
	sig, _ := rsa.SignPKCS1v15(nil, acsKey, crypto.SHA256, dig[:])
	if err := leaf.CheckSignature(x509.SHA256WithRSA, []byte("acsSignedContent"), sig); err != nil {
		t.Fatal(err)
	}
}

func TestRefusesRequestsWithoutProofOrWithBadNames(t *testing.T) {
	h, _ := fakeHSM(t)
	defer h.Close()
	iss, _ := New(h.URL, "scheme-ca")
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := csrFor(t, k, "DIFME ACS")
	der[len(der)-5] ^= 0xff // broken signature: no proof of possession
	if _, err := iss.IssueACSSigning(der); err == nil {
		t.Fatal("tampered request accepted")
	}
	if _, err := iss.IssueACSSigning(csrFor(t, k, "ACS, O=Evil")); err == nil {
		t.Fatal("bad common name accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := iss.IssueACSSigning(csrFor(t, small, "DIFME ACS")); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

// Package ca is the card scheme's certificate authority (owner 2026-11-24: certificates issued by the card scheme
// simulator; keys only in the emulated TEE). The CA key (scheme-ca) lives in the security module: this package builds
// each certificate and has the module sign its SHA-256 digest (POST /v1/ca/<key>/sign-digest, which only the scheme
// simulator may call). The root certificate is the module's self-signed CA certificate for that key.
//
// Profile acs-signing: the ACS's acsSignedContent signing certificate (EMV 3DS 2.3.1). The ACS sends a PKCS#10 request
// made and signed in the security module with its acs-sign key (proof of possession); the chain returned is
// [leaf, root].
package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"time"
)

// Issuer signs certificates with a CA key held in the security module.
type Issuer struct {
	hsmURL, key string
	Root        *x509.Certificate
	c           *http.Client
	Now         func() time.Time
}

// New fetches the CA certificate of key (e.g. "scheme-ca") from the security module.
func New(hsmURL, key string) (*Issuer, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	r, err := c.Get(hsmURL + "/v1/certs/" + key)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out struct {
		X5C string `json:"x5c"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 {
		return nil, fmt.Errorf("security module CA certificate %s: HTTP %d", key, r.StatusCode)
	}
	der, err := base64.StdEncoding.DecodeString(out.X5C)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !root.IsCA {
		return nil, fmt.Errorf("%s: not a CA certificate", key)
	}
	return &Issuer{hsmURL: hsmURL, key: key, Root: root, c: c, Now: time.Now}, nil
}

// Public implements crypto.Signer.
func (i *Issuer) Public() crypto.PublicKey { return i.Root.PublicKey }

// Sign implements crypto.Signer for x509.CreateCertificate: RSASSA-PKCS1-v1_5 over a SHA-256 digest, in the module.
func (i *Issuer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("scheme CA signs sha256WithRSAEncryption only")
	}
	body, _ := json.Marshal(map[string]string{"digest": hex.EncodeToString(digest)})
	r, err := i.c.Post(i.hsmURL+"/v1/ca/"+i.key+"/sign-digest", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil || r.StatusCode != 200 {
		return nil, fmt.Errorf("security module CA signature: HTTP %d %s", r.StatusCode, out.Error)
	}
	return hex.DecodeString(out.Signature)
}

var commonName = regexp.MustCompile(`^[A-Za-z0-9 .-]{1,64}$`)

// IssueACSSigning issues the ACS signing certificate for a PKCS#10 request (DER) whose signature proves possession.
func (i *Issuer) IssueACSSigning(csrDER []byte) ([]*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request: proof of possession failed: %w", err)
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, errors.New("certificate request: RSA key of 2048 bits or more required")
	}
	if !commonName.MatchString(csr.Subject.CommonName) {
		return nil, errors.New("certificate request: common name letters, digits, space, dot, dash (1-64)")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := i.Now()
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: csr.Subject.CommonName, Organization: []string{"DIFME ACS (issuer)"}},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.AddDate(1, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
		AuthorityKeyId:     i.Root.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.Root, pub, i)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := leaf.CheckSignatureFrom(i.Root); err != nil {
		return nil, fmt.Errorf("issued certificate does not verify: %w", err)
	}
	return []*x509.Certificate{leaf, i.Root}, nil
}

// Handler serves POST /ca/acs-signing: {"csr": base64 DER} -> {"chain": [base64 DER, leaf first]}.
func (i *Issuer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ca/acs-signing" {
			http.Error(w, "POST /ca/acs-signing", http.StatusNotFound)
			return
		}
		var in struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
			http.Error(w, "body: {\"csr\": base64 DER}", http.StatusBadRequest)
			return
		}
		der, err := base64.StdEncoding.DecodeString(in.CSR)
		if err != nil {
			http.Error(w, "csr: base64 DER", http.StatusBadRequest)
			return
		}
		chain, err := i.IssueACSSigning(der)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out := struct {
			Chain []string `json:"chain"`
		}{}
		for _, c := range chain {
			out.Chain = append(out.Chain, base64.StdEncoding.EncodeToString(c.Raw))
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

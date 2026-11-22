package acs

// App channel security (deviceChannel 01, EMV 3DS 2.3.1 §6.2): the 3DS SDK sends an ephemeral P-256 public key in
// the AReq (sdkEphemPubKey). The ACS answers with acsSignedContent, a JWS (PS256, ACS certificate in x5c) over its own
// ephemeral key, the SDK's key and the acsURL. Both sides derive the content key from ECDH with ConcatKDF
// (SHA-256, 256 bits, AlgorithmID and PartyUInfo empty, PartyVInfo = SDK reference number), and exchange CReq/CRes as
// JWE compact with "alg":"dir": A128CBC-HS256 (the whole 32-byte key both ways) or A128GCM (SDK->ACS first 16 bytes,
// ACS->SDK last 16 bytes).

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// JWK is an EC public key (P-256).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func jwkOf(pub *ecdh.PublicKey) JWK {
	b := pub.Bytes() // 0x04 || X || Y
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(b[1:33]), Y: b64.EncodeToString(b[33:65])}
}

func (j JWK) public() (*ecdh.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, errors.New("sdkEphemPubKey: EC P-256 required")
	}
	x, err1 := b64.DecodeString(j.X)
	y, err2 := b64.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("sdkEphemPubKey: bad coordinates")
	}
	return ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...)) // rejects points not on the curve
}

// ConcatKDF per NIST SP 800-56A / RFC 7518 §4.6.2 with the EMV 3DS parameters.
func ConcatKDF(z []byte, sdkReferenceNumber string) []byte {
	var otherInfo []byte
	lp := func(b []byte) {
		otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(len(b)))
		otherInfo = append(otherInfo, b...)
	}
	lp(nil)                        // AlgorithmID
	lp(nil)                        // PartyUInfo
	lp([]byte(sdkReferenceNumber)) // PartyVInfo
	otherInfo = binary.BigEndian.AppendUint32(otherInfo, 256)
	h := sha256.New()
	h.Write([]byte{0, 0, 0, 1})
	h.Write(z)
	h.Write(otherInfo)
	return h.Sum(nil)
}

// AppSession is one transaction's app-channel keys.
type AppSession struct {
	key []byte // 32 bytes from ConcatKDF
}

// Signer signs acsSignedContent (the ACS's RSA key and certificate chain, leaf first).
type Signer struct {
	Key   *rsa.PrivateKey
	Chain []*x509.Certificate
}

// NewAppSession runs the ACS side of the key agreement and returns the session plus acsSignedContent.
func NewAppSession(sdkPub JWK, sdkReferenceNumber, acsURL string, s *Signer) (*AppSession, string, error) {
	pub, err := sdkPub.public()
	if err != nil {
		return nil, "", err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	z, err := eph.ECDH(pub)
	if err != nil {
		return nil, "", err
	}
	payload, _ := json.Marshal(map[string]any{"acsURL": acsURL, "acsEphemPubKey": jwkOf(eph.PublicKey()), "sdkEphemPubKey": sdkPub})
	jws, err := s.sign(payload)
	if err != nil {
		return nil, "", err
	}
	return &AppSession{key: ConcatKDF(z, sdkReferenceNumber)}, jws, nil
}

func (s *Signer) sign(payload []byte) (string, error) {
	var x5c []string
	for _, c := range s.Chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "PS256", "x5c": x5c})
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPSS(rand.Reader, s.Key, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return in + "." + b64.EncodeToString(sig), nil
}

// DecryptCReq opens a JWE CReq from the SDK.
func (s *AppSession) DecryptCReq(jwe string) ([]byte, string, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, "", errors.New("JWE compact with alg dir (empty encrypted key) required")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	var hdr struct{ Alg, Enc string }
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr.Alg != "dir" {
		return nil, "", errors.New("JWE header: alg dir required")
	}
	iv, err1 := b64.DecodeString(parts[2])
	ct, err2 := b64.DecodeString(parts[3])
	tag, err3 := b64.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, "", errors.New("JWE: bad base64url")
	}
	aad := []byte(parts[0])
	switch hdr.Enc {
	case "A128CBC-HS256":
		pt, err := cbcHSOpen(s.key, iv, ct, tag, aad)
		return pt, hdr.Enc, err
	case "A128GCM":
		pt, err := gcmOpen(s.key[:16], iv, ct, tag, aad)
		return pt, hdr.Enc, err
	}
	return nil, "", fmt.Errorf("JWE enc %q not supported", hdr.Enc)
}

// EncryptCRes seals a CRes for the SDK with the same enc the SDK used.
func (s *AppSession) EncryptCRes(plaintext []byte, enc, kid string) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "dir", "enc": enc, "kid": kid})
	h := b64.EncodeToString(hdr)
	var iv, ct, tag []byte
	var err error
	switch enc {
	case "A128CBC-HS256":
		iv, ct, tag, err = cbcHSSeal(s.key, plaintext, []byte(h))
	case "A128GCM":
		iv, ct, tag, err = gcmSeal(s.key[16:], plaintext, []byte(h))
	default:
		err = fmt.Errorf("JWE enc %q not supported", enc)
	}
	if err != nil {
		return "", err
	}
	return h + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct) + "." + b64.EncodeToString(tag), nil
}

// A128CBC-HS256 (RFC 7518 §5.2.3): MAC key = first 16 bytes, encryption key = last 16 bytes.
func cbcHSTag(macKey, aad, iv, ct []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(aad)
	m.Write(iv)
	m.Write(ct)
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(aad))*8))
	return m.Sum(nil)[:16]
}

func cbcHSSeal(key, pt, aad []byte) (iv, ct, tag []byte, err error) {
	iv = make([]byte, 16)
	if _, err = rand.Read(iv); err != nil {
		return
	}
	pad := 16 - len(pt)%16
	p := append(append([]byte{}, pt...), bytesRepeat(byte(pad), pad)...)
	blk, _ := aes.NewCipher(key[16:])
	ct = make([]byte, len(p))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, p)
	return iv, ct, cbcHSTag(key[:16], aad, iv, ct), nil
}

func cbcHSOpen(key, iv, ct, tag, aad []byte) ([]byte, error) {
	if len(iv) != 16 || len(ct) == 0 || len(ct)%16 != 0 || !hmac.Equal(tag, cbcHSTag(key[:16], aad, iv, ct)) {
		return nil, errors.New("JWE authentication failed")
	}
	blk, _ := aes.NewCipher(key[16:])
	p := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(p, ct)
	pad := int(p[len(p)-1])
	if pad == 0 || pad > 16 {
		return nil, errors.New("JWE padding")
	}
	return p[:len(p)-pad], nil
}

func gcmSeal(key, pt, aad []byte) (iv, ct, tag []byte, err error) {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	iv = make([]byte, 12)
	if _, err = rand.Read(iv); err != nil {
		return
	}
	out := g.Seal(nil, iv, pt, aad)
	return iv, out[:len(out)-16], out[len(out)-16:], nil
}

func gcmOpen(key, iv, ct, tag, aad []byte) ([]byte, error) {
	blk, _ := aes.NewCipher(key)
	g, err := cipher.NewGCM(blk)
	if err != nil || len(iv) != 12 {
		return nil, errors.New("JWE: bad GCM parameters")
	}
	return g.Open(nil, iv, append(append([]byte{}, ct...), tag...), aad)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// DevSigner makes a self-signed ACS signing certificate (development only; production uses the scheme-issued ACS
// certificate chain from OpenBao).
func DevSigner() (*Signer, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "DIFME ACS (dev)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Signer{Key: k, Chain: []*x509.Certificate{c}}, nil
}

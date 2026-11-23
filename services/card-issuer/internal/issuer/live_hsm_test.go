package issuer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Against the real security module (CARD_ISSUER_LIVE_HSM=http://127.0.0.1:18702, dev keys: imk-ac from components
// 0123456789ABCDEFFEDCBA9876543210, zpk, pvk, aes-pin). Skipped otherwise.
func liveHSM(t *testing.T) *HSMClient {
	u := os.Getenv("CARD_ISSUER_LIVE_HSM")
	if u == "" {
		t.Skip("CARD_ISSUER_LIVE_HSM not set")
	}
	return NewHSMClient(u)
}

func TestLiveChipClearingCryptograms(t *testing.T) {
	h := liveHSM(t)
	ctx := context.Background()
	for _, v := range chipVectors {
		c, err := parseChip(v.pan, v.f55)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := h.VerifyAC(ctx, c); err != nil || !ok {
			t.Errorf("%s: %v %v", v.name, ok, err)
		}
		flip := map[byte]string{'0': "1"}[c.TxnData[11]]
		if flip == "" {
			flip = "0"
		}
		c.TxnData = c.TxnData[:11] + flip + c.TxnData[12:] // another amount
		if ok, err := h.VerifyAC(ctx, c); err != nil || ok {
			t.Errorf("%s altered: %v %v", v.name, ok, err)
		}
	}
}

// The JWE from the module, opened here with Go's own ECDH, Concat KDF and AES-GCM (an implementation independent of
// the module's Java code).
func TestLivePINRevealToAnECKey(t *testing.T) {
	h := liveHSM(t)
	ctx := context.Background()
	i := New("437551", newLedger(), h, NewMemStore())
	i.Audit = func(context.Context, string, ...any) {}
	c, err := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "live"})
	if err != nil {
		t.Fatal(err)
	}
	if err := i.GeneratePIN(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	jwe, err := i.RevealPIN(ctx, c.ID, base64.StdEncoding.EncodeToString(spki))
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(jwe, ".")
	hdrJSON, _ := base64.RawURLEncoding.DecodeString(p[0])
	var hdr struct {
		Alg, Enc, Kid string
		Epk           struct{ X, Y string }
	}
	_ = json.Unmarshal(hdrJSON, &hdr)
	if hdr.Alg != "ECDH-ES" || hdr.Enc != "A256GCM" || hdr.Kid != c.PANFull[12:] || p[1] != "" {
		t.Fatalf("header %s", hdrJSON)
	}
	x, _ := base64.RawURLEncoding.DecodeString(hdr.Epk.X)
	y, _ := base64.RawURLEncoding.DecodeString(hdr.Epk.Y)
	eph, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	me, _ := priv.ECDH()
	z, _ := me.ECDH(eph)
	other := binary.BigEndian.AppendUint32(nil, 7)
	other = append(other, "A256GCM"...)
	other = binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(other, 0), 0), 256)
	d := sha256.Sum256(append(append([]byte{0, 0, 0, 1}, z...), other...))
	blk, _ := aes.NewCipher(d[:])
	g, _ := cipher.NewGCM(blk)
	iv, _ := base64.RawURLEncoding.DecodeString(p[2])
	ct, _ := base64.RawURLEncoding.DecodeString(p[3])
	tag, _ := base64.RawURLEncoding.DecodeString(p[4])
	pin, err := g.Open(nil, iv, append(ct, tag...), []byte(p[0]))
	if err != nil || len(pin) != 4 || strings.Trim(string(pin), "0123456789") != "" {
		t.Fatalf("decrypt: %v %q", err, pin)
	}
	// the revealed PIN is the card's PIN: as an ISO 0 block under the ZPK it verifies against the stored PVV
	card, _ := i.store.Card(ctx, c.ID)
	if card.PendingPIN != "" {
		t.Fatal("pending PIN kept after reveal")
	}
	blockZPK := iso0UnderDevZPK(t, string(pin), c.PANFull)
	if ok, err := h.VerifyPVV(ctx, c.PANFull, blockZPK, card.PVV); err != nil || !ok {
		t.Fatalf("revealed PIN does not verify: %v %v", ok, err)
	}
	if _, err := i.RevealPIN(ctx, c.ID, base64.StdEncoding.EncodeToString(spki)); err != ErrNoPendingPIN {
		t.Fatalf("second reveal: %v", err)
	}
}

// iso0UnderDevZPK forms an ISO 9564 format 0 block for pin and encrypts it under the dev ZPK (components
// 1C1C…2A2A, the live script's key) with 3DES-ECB.
func iso0UnderDevZPK(t *testing.T, pin, pan string) string {
	zpk := os.Getenv("CARD_ISSUER_LIVE_ZPK")
	if zpk == "" {
		t.Skip("CARD_ISSUER_LIVE_ZPK (dev ZPK components) not set")
	}
	k, _ := hex.DecodeString(zpk)
	blk, err := newTDES(append(k, k[:8]...))
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := hex.DecodeString((("0" + string(rune('0'+len(pin))) + pin + "FFFFFFFFFFFFFF")[:16]))
	pp, _ := hex.DecodeString("0000" + pan[len(pan)-13:len(pan)-1])
	out := make([]byte, 8)
	for k := range pb {
		pb[k] ^= pp[k]
	}
	blk.Encrypt(out, pb)
	return strings.ToUpper(hex.EncodeToString(out))
}

func newTDES(k []byte) (cipher.Block, error) { return des.NewTripleDESCipher(k) }

// The bureau file from the real module through card-issuer: header, one record per card, trailer.
func TestLivePersoFile(t *testing.T) {
	h := liveHSM(t)
	ctx := context.Background()
	i := New("437551", newLedger(), h, NewMemStore())
	i.Audit = func(context.Context, string, ...any) {}
	i.PersoIssuerCert = &IssuerCert{CAIndex: "92", Cert: strings.Repeat("AB", 176), Exponent: "010001"}
	a, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "x"})
	b, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "y"})
	f, err := i.Perso(ctx, []string{a.ID, b.ID})
	if err != nil {
		t.Fatal(err)
	}
	l := strings.Split(strings.TrimSuffix(f, "\n"), "\n")
	if len(l) != 4 || !strings.HasPrefix(l[0], "HDR|FORMAT=DIFME-PERSO/1|ISSUER=437551") || !strings.Contains(l[1], "|PAN="+a.PANFull+"|") ||
		!strings.Contains(l[2], "|MK_AC=B") || !strings.HasPrefix(l[3], "TRL|COUNT=2|SHA256=") {
		t.Fatalf("file:\n%s", f)
	}
	sum := sha256.Sum256([]byte(l[0] + "\n" + l[1] + "\n" + l[2] + "\n"))
	if !strings.HasSuffix(l[3], strings.ToUpper(hex.EncodeToString(sum[:]))) {
		t.Fatal("trailer digest")
	}
}

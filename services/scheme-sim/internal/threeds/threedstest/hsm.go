// Package threedstest provides an in-process stand-in for the security module's CAVV functions, for unit tests
// only: the Visa CVV algorithm with a clear test key (the real module holds keys under its LMK). Its values are
// checked against psec and services/hsm in cavv_test.go.
package threedstest

import (
	"context"
	"crypto/des"
	"encoding/hex"
	"strings"
)

// TestCVK is the test key used across DIFME's CVV/CAVV tests (services/hsm SecurityModuleTest).
const TestCVK = "0123456789ABCDEFFEDCBA9876543210"

type HSM struct{ Key string }

func New() *HSM { return &HSM{Key: TestCVK} }

// CVV is the Visa CVV algorithm over PAN, a 4-digit field and a 3-digit field.
func CVV(keyHex, pan, four, three string) string {
	k, _ := hex.DecodeString(keyHex)
	a, _ := des.NewCipher(k[:8])
	b, _ := des.NewCipher(k[8:16])
	d := pan + four + three
	d += strings.Repeat("0", 32-len(d)%32)
	b1, _ := hex.DecodeString(d[:16])
	b2, _ := hex.DecodeString(d[16:32])
	r := make([]byte, 8)
	a.Encrypt(r, b1)
	for i := range r {
		r[i] ^= b2[i]
	}
	a.Encrypt(r, r)
	b.Decrypt(r, r)
	a.Encrypt(r, r)
	h := strings.ToUpper(hex.EncodeToString(r))
	var out []byte
	for _, c := range h {
		if c >= '0' && c <= '9' {
			out = append(out, byte(c))
		}
	}
	for _, c := range h {
		if c >= 'A' && c <= 'F' {
			out = append(out, byte('0'+c-'A'))
		}
	}
	return string(out[:3])
}

func (h *HSM) CAVV(_ context.Context, pan, upn, authrc, sfarc string) (string, error) {
	return CVV(h.Key, pan, upn, authrc+sfarc), nil
}

func (h *HSM) VerifyCAVV(ctx context.Context, pan, cvv, upn, authrc, sfarc string) (bool, error) {
	v, _ := h.CAVV(ctx, pan, upn, authrc, sfarc)
	return v == cvv, nil
}

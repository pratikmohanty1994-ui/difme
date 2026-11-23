package issuer

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Personalisation file for the card bureau (DIFME-PERSO/1, format in services/hsm PersoFile.java): the security
// module derives each card's ICC keys, makes its ICC RSA key and certificate (signed with the issuer key it holds) and
// its iCVV, all keys under the bureau transport key. card-issuer chooses the cards and adds nothing secret.

// IssuerCert is the issuer public key certificate from the scheme CA (public data): CA key index (8F), certificate
// (90), remainder (92, may be empty) and exponent (9F32), hex.
type IssuerCert struct{ CAIndex, Cert, Remainder, Exponent string }

var hexRE = regexp.MustCompile(`^([0-9A-Fa-f]{2})*$`)

// ParseIssuerCert reads "8F:90:92:9F32" (CARD_PERSO_ISSUER_CERT).
func ParseIssuerCert(s string) (*IssuerCert, error) {
	p := strings.Split(strings.TrimSpace(s), ":")
	if len(p) != 4 || p[0] == "" || p[1] == "" || p[3] == "" {
		return nil, fmt.Errorf("issuer certificate: CA index:certificate:remainder:exponent (hex)")
	}
	for _, v := range p {
		if !hexRE.MatchString(v) {
			return nil, fmt.Errorf("issuer certificate: hex fields")
		}
	}
	return &IssuerCert{CAIndex: p[0], Cert: p[1], Remainder: p[2], Exponent: p[3]}, nil
}

// Perso returns the bureau file for the given cards (active cards only, at most 500).
func (i *Issuer) Perso(ctx context.Context, ids []string) (string, error) {
	if i.PersoIssuerCert == nil {
		return "", fmt.Errorf("%w: issuer certificate not configured (CARD_PERSO_ISSUER_CERT)", ErrInvalid)
	}
	if len(ids) == 0 || len(ids) > 500 {
		return "", fmt.Errorf("%w: cardIds: 1 to 500", ErrInvalid)
	}
	cards := make([]string, 0, len(ids))
	for _, id := range ids {
		c, err := i.store.Card(ctx, id)
		if err != nil {
			return "", err
		}
		if c.Status != "ACTIVE" {
			return "", fmt.Errorf("%w: card %s is %s", ErrInvalid, id, c.Status)
		}
		cards = append(cards, c.PAN+":00:"+c.Expiry)
	}
	f, err := i.hsm.PersoBatch(ctx, i.BIN, cards, *i.PersoIssuerCert)
	i.Audit(ctx, "perso_file", "cards", fmt.Sprint(len(ids)), "outcome", map[bool]string{true: "made", false: "failed"}[err == nil])
	return f, err
}

func (h *HSMClient) PersoBatch(ctx context.Context, bin string, cards []string, ic IssuerCert) (string, error) {
	v, err := h.call(ctx, "/v1/perso/batch", map[string]string{"issuer": bin, "cards": strings.Join(cards, ";"), "caIndex": ic.CAIndex,
		"issuerCert": ic.Cert, "issuerRemainder": ic.Remainder, "issuerExponent": ic.Exponent}, "file")
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(v)
	return string(b), err
}

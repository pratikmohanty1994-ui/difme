package issuer

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

// Chip cryptogram verification at clearing (ADR-026, plan phase 3 "TC/AAC verification at clearing"): a card-present
// presentment carries the chip data (ISO 8583 field 55, BER-TLV) with the card's final cryptogram, a TC (approved
// offline or after online approval), an AAC (declined) or an ARQC. card-issuer rebuilds the transaction data the card
// signed and has the security module verify the cryptogram with the ARQC function (same keys and session-key
// derivation; the ARPC it returns is discarded).

// chipAC is what the security module needs to check one application cryptogram.
type chipAC struct {
	PAN     string
	CVN     string // hsm Cvn name: VISA_10, VISA_18, VISA_22, MASTERCARD_16/17/20/21
	Kind    string // TC, AAC, ARQC (from 9F27)
	AC      string // 9F26
	ATC     string // 9F36
	UN      string // 9F37
	PSN     string // 5F34 as two digits (00 when absent)
	TxnData string // the data the card MACed, CDOL order plus the scheme's issuer application data part
	ARC     string // placeholder response code / CSU for the ARPC the module also returns (unused here)
}

// parseTLV decodes BER-TLV (primitive tags only at the top level; constructed templates are descended into).
func parseTLV(b []byte, out map[string][]byte) error {
	for len(b) > 0 {
		if b[0] == 0x00 || b[0] == 0xFF { // padding between objects
			b = b[1:]
			continue
		}
		t := 1
		if b[0]&0x1F == 0x1F {
			for t < len(b) && b[t]&0x80 != 0 {
				t++
			}
			t++
		}
		if t >= len(b) {
			return fmt.Errorf("truncated tag")
		}
		tag := strings.ToUpper(hex.EncodeToString(b[:t]))
		n, l := int(b[t]), 1
		if n&0x80 != 0 {
			k := n & 0x7F
			if k == 0 || k > 2 || t+1+k > len(b) {
				return fmt.Errorf("bad length for tag %s", tag)
			}
			n = 0
			for _, c := range b[t+1 : t+1+k] {
				n = n<<8 | int(c)
			}
			l += k
		}
		start := t + l
		if start+n > len(b) {
			return fmt.Errorf("tag %s: value runs past the end", tag)
		}
		v := b[start : start+n]
		if b[0]&0x20 != 0 { // constructed
			if err := parseTLV(v, out); err != nil {
				return err
			}
		} else {
			out[tag] = v
		}
		b = b[start+n:]
	}
	return nil
}

// parseChip turns field 55 into the cryptogram check for the card's scheme (from the PAN: 4 Visa, 2/5 Mastercard).
func parseChip(pan, field55 string) (chipAC, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(field55))
	if err != nil || len(raw) == 0 {
		return chipAC{}, fmt.Errorf("%w: icc: field 55 in hex", ErrInvalid)
	}
	t := map[string][]byte{}
	if err := parseTLV(raw, t); err != nil {
		return chipAC{}, fmt.Errorf("%w: icc: %v", ErrInvalid, err)
	}
	need := map[string]int{"9F26": 8, "9F27": 1, "9F10": 0, "9F36": 2, "9F37": 4, "9F02": 6, "9F1A": 2, "95": 5, "5F2A": 2, "9A": 3, "9C": 1, "82": 2}
	for tag, n := range need {
		if v, ok := t[tag]; !ok || (n > 0 && len(v) != n) {
			return chipAC{}, fmt.Errorf("%w: icc: tag %s missing or of the wrong length", ErrInvalid, tag)
		}
	}
	if v, ok := t["5A"]; ok && strings.TrimRight(strings.ToUpper(hex.EncodeToString(v)), "F") != pan {
		return chipAC{}, fmt.Errorf("%w: icc: tag 5A is another card", ErrInvalid)
	}
	other, ok := t["9F03"]
	if !ok {
		other = make([]byte, 6)
	} else if len(other) != 6 {
		return chipAC{}, fmt.Errorf("%w: icc: tag 9F03 of the wrong length", ErrInvalid)
	}
	psn := "00"
	if v, ok := t["5F34"]; ok && len(v) == 1 {
		psn = fmt.Sprintf("%02X", v[0])
		if strings.Trim(psn, "0123456789") != "" {
			return chipAC{}, fmt.Errorf("%w: icc: tag 5F34 not BCD", ErrInvalid)
		}
	}
	cdol := hx(t["9F02"]) + hx(other) + hx(t["9F1A"]) + hx(t["95"]) + hx(t["5F2A"]) + hx(t["9A"]) + hx(t["9C"]) + hx(t["9F37"]) + hx(t["82"]) + hx(t["9F36"])
	iad := t["9F10"]
	c := chipAC{PAN: pan, AC: hx(t["9F26"]), ATC: hx(t["9F36"]), UN: hx(t["9F37"]), PSN: psn, ARC: "3030"}
	switch t["9F27"][0] & 0xC0 {
	case 0x40:
		c.Kind = "TC"
	case 0x80:
		c.Kind = "ARQC"
	default:
		c.Kind = "AAC"
	}
	switch {
	case strings.HasPrefix(pan, "4"): // Visa VIS: IAD format 0/1/3 (length 06/07, CVN in byte 3) or format 2 (1F, CVN in byte 2)
		switch {
		case len(iad) >= 7 && iad[0] <= 0x1E && iad[2] == 0x0A: // CVN 10: CVR (length byte + 3 bytes)
			c.CVN, c.TxnData = "VISA_10", cdol+hx(iad[3:7])
		case len(iad) >= 7 && iad[0] <= 0x1E && iad[2] == 0x12: // CVN 18: the whole IAD
			c.CVN, c.TxnData, c.ARC = "VISA_18", cdol+hx(iad), "00000000"
		case len(iad) >= 2 && iad[0] == 0x1F && iad[1] == 0x22: // CVN 22 (format 2): the whole IAD
			c.CVN, c.TxnData, c.ARC = "VISA_22", cdol+hx(iad), "00000000"
		default:
			return chipAC{}, fmt.Errorf("%w: icc: Visa cryptogram version not supported", ErrInvalid)
		}
	case strings.HasPrefix(pan, "5") || strings.HasPrefix(pan, "2"): // M/Chip: KDI, CVN, CVR(6), DAC/IDN(2), counters(8)
		if len(iad) < 8 {
			return chipAC{}, fmt.Errorf("%w: icc: Mastercard IAD too short", ErrInvalid)
		}
		cvr := hx(iad[2:8])
		switch iad[1] {
		case 0x10:
			c.CVN, c.TxnData = "MASTERCARD_16", cdol+cvr
		case 0x14:
			c.CVN, c.TxnData = "MASTERCARD_20", cdol+cvr
		case 0x11, 0x15:
			if len(iad) < 18 {
				return chipAC{}, fmt.Errorf("%w: icc: Mastercard IAD without counters", ErrInvalid)
			}
			c.CVN, c.TxnData = map[byte]string{0x11: "MASTERCARD_17", 0x15: "MASTERCARD_21"}[iad[1]], cdol+cvr+hx(iad[10:18])
		default:
			return chipAC{}, fmt.Errorf("%w: icc: Mastercard cryptogram version not supported", ErrInvalid)
		}
	default:
		return chipAC{}, fmt.Errorf("%w: icc: scheme not supported for chip clearing", ErrInvalid)
	}
	return c, nil
}

func hx(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// verifyChip checks the cryptogram in field 55 with the security module and returns its kind (TC, AAC, ARQC), or
// "INVALID" when it does not verify.
func (i *Issuer) verifyChip(ctx context.Context, pan, field55 string) (string, error) {
	c, err := parseChip(pan, field55)
	if err != nil {
		return "", err
	}
	ok, err := i.hsm.VerifyAC(ctx, c)
	if err != nil {
		return "", fmt.Errorf("security module: %w", err)
	}
	if !ok {
		return "INVALID", nil
	}
	return c.Kind, nil
}

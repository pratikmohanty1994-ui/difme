package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Field 55 of clearing records whose cryptograms pyemv 1.5 generated (VisaCVN10/18, MasterCardCVN16/21 generate_ac,
// IMK 0123456789ABCDEFFEDCBA9876543210). The parser must rebuild exactly the data pyemv MACed; the security module
// verifies the same cryptograms over that data in services/hsm ChipClearingTest.
var chipVectors = []struct {
	name, pan, f55, cvn, kind, psn, atc, un, txn, ac string
}{
	{"VISA_10 TC", "4375510000000001",
		"9F2608FF42664AA283A57E9F2701409F100706010A036000009F360200079F3704A1B2C3D49F02060000000125009F03060000000000009F1A020356950500000000005F2A0203569A032611239C0100820218005F340100",
		"VISA_10", "TC", "00", "0007", "A1B2C3D4", "00000001250000000000000003560000000000035626112300A1B2C3D41800000703600000", "FF42664AA283A57E"},
	{"VISA_18 TC", "4375510000000001",
		"9F2608C68C301A5BED545E9F2701409F1007060112036000009F360200129F37040BADF00D9F02060000000049999F03060000000000009F1A020356950500000080005F2A0203569A032611239C0100820218005F340100",
		"VISA_18", "TC", "00", "0012", "0BADF00D", "000000004999000000000000035600000080000356261123000BADF00D1800001206011203600000", "C68C301A5BED545E"},
	{"VISA_18 AAC", "4375510000000001",
		"9F2608754FAC2DA51CD9CA9F2701009F1007060112039000009F360200139F37040BADF00E9F02060000000049999F03060000000000009F1A020356950580000480005F2A0203569A032611239C0100820218005F340100",
		"VISA_18", "AAC", "00", "0013", "0BADF00E", "000000004999000000000000035680000480000356261123000BADF00E1800001306011203900000", "754FAC2DA51CD9CA"},
	{"MASTERCARD_16 TC", "5413330089020011",
		"9F260898D4C3A7EB6ECDD49F2701409F10130110600002000000AABB0000000000000000FF9F3602002A9F3704123456799F02060000000200009F03060000000000009F1A020356950500000000005F2A0203569A032611239C0100820218005F340101",
		"MASTERCARD_16", "TC", "01", "002A", "12345679", "00000002000000000000000003560000000000035626112300123456791800002A600002000000", "98D4C3A7EB6ECDD4"},
	{"MASTERCARD_21 TC", "5413330089020011",
		"9F2608E41040D34850E8159F2701409F10130115600002000000AABB0102030405060708FF9F3602002B9F37041234567A9F02060000000200009F03060000000000009F1A020356950500000000005F2A0203569A032611239C0100820218005F340101",
		"MASTERCARD_21", "TC", "01", "002B", "1234567A", "000000020000000000000000035600000000000356261123001234567A1800002B6000020000000102030405060708", "E41040D34850E815"},
}

func TestParseChipMatchesPyemvData(t *testing.T) {
	for _, v := range chipVectors {
		c, err := parseChip(v.pan, v.f55)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if c.CVN != v.cvn || c.Kind != v.kind || c.PSN != v.psn || c.ATC != v.atc || c.UN != v.un || c.TxnData != v.txn || c.AC != v.ac || c.PAN != v.pan {
			t.Errorf("%s: %+v", v.name, c)
		}
	}
	// wrapped in a constructed template (70) and with tag order changed: same result
	v := chipVectors[1]
	body := v.f55[len("9F2608C68C301A5BED545E"):] + "9F2608C68C301A5BED545E"
	if c, err := parseChip(v.pan, "70"+"81"+strings.ToUpper(hexLen(len(body)/2))+body); err != nil || c.TxnData != v.txn {
		t.Errorf("template: %v %+v", err, c)
	}
	bad := []struct{ name, pan, f55 string }{
		{"not hex", v.pan, "9F26ZZ"},
		{"truncated", v.pan, v.f55[:len(v.f55)-4]},
		{"no cryptogram", v.pan, strings.Replace(v.f55, "9F2608C68C301A5BED545E", "", 1)},
		{"other card in 5A", v.pan, v.f55 + "5A084375510000000019"},
		{"unknown Visa CVN", v.pan, strings.Replace(v.f55, "9F100706011203", "9F100706013303", 1)},
		{"Visa data for a Mastercard", "5413330089020011", v.f55},
		{"Amex", "371449635398431", v.f55},
	}
	for _, b := range bad {
		if _, err := parseChip(b.pan, b.f55); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", b.name, err)
		}
	}
}

func hexLen(n int) string {
	return strings.ToUpper(string("0123456789abcdef"[n>>4]) + string("0123456789abcdef"[n&15]))
}

// chipHSM accepts exactly the pyemv vectors (as the real module does, see ChipClearingTest).
type chipHSM struct{ fakeHSM }

func (chipHSM) VerifyAC(_ context.Context, c chipAC) (bool, error) {
	for _, v := range chipVectors {
		if c.AC == v.ac {
			return c.TxnData == v.txn && c.CVN == v.cvn && c.ATC == v.atc && c.PSN == v.psn, nil
		}
	}
	return false, nil
}

func TestClearingVerifiesTheChipCryptogram(t *testing.T) {
	l := newLedger()
	st := NewMemStore()
	i := New("437551", l, chipHSM{}, st)
	ctx := context.Background()
	card := Card{ID: "card-chip", PAN: "4375510000000001", MaskedPAN: Mask("4375510000000001"), Expiry: "3012", Product: Debit, Account: 1, Status: "ACTIVE", Holder: "p"}
	_ = st.PutCard(ctx, card)
	auth := func() Auth {
		a, _ := i.Authorise(ctx, AuthRequest{PAN: card.PAN, AmountMinor: 4_999})
		if a.Code != Approved {
			t.Fatalf("%+v", a)
		}
		return a
	}
	// TC verifies: posted
	a := auth()
	got, err := i.ClearPresentment(ctx, a.ID, 4_999, chipVectors[1].f55)
	if err != nil || got.State != "CLEARED" || got.Chip != "TC" || l.balance[1] != 100_000-4_999 {
		t.Fatalf("TC: %v %+v balance %d", err, got, l.balance[1])
	}
	if c, _ := st.Card(ctx, card.ID); c.LastATC != 0x12 {
		t.Fatalf("last ATC after the TC: %d", c.LastATC)
	}
	// the same TC again (ATC 0012 already cleared): a replay, not posted
	r := auth()
	got, err = i.ClearPresentment(ctx, r.ID, 4_999, chipVectors[1].f55)
	if !errors.Is(err, ErrInvalid) || got.State != "HELD" || got.Chip != "REPLAY" || l.balance[1] != 100_000-4_999 {
		t.Fatalf("replayed TC: %v %+v balance %d", err, got, l.balance[1])
	}
	// a genuine TC with a lower ATC (0007 < 0012): also refused
	got, err = i.ClearPresentment(ctx, r.ID, 4_999, chipVectors[0].f55)
	if !errors.Is(err, ErrInvalid) || got.Chip != "REPLAY" {
		t.Fatalf("lower ATC: %v %+v", err, got)
	}
	_, _ = i.Reverse(ctx, r.ID)
	// AAC (the card declined): not posted, kept held and marked
	b := auth()
	got, err = i.ClearPresentment(ctx, b.ID, 4_999, chipVectors[2].f55)
	if !errors.Is(err, ErrInvalid) || got.State != "HELD" || got.Chip != "AAC" {
		t.Fatalf("AAC: %v %+v", err, got)
	}
	// a cryptogram altered in transit (amount in 9F02 changed): does not verify, not posted
	tampered := strings.Replace(chipVectors[1].f55, "9F0206000000004999", "9F0206000000004990", 1)
	got, err = i.ClearPresentment(ctx, b.ID, 4_999, tampered)
	if !errors.Is(err, ErrInvalid) || got.State != "HELD" || got.Chip != "INVALID" {
		t.Fatalf("tampered: %v %+v", err, got)
	}
	if stored, _ := st.Auth(ctx, b.ID); stored.Chip != "INVALID" || stored.State != "HELD" {
		t.Fatalf("stored for review: %+v", stored)
	}
	// malformed field 55: refused before the security module, nothing recorded
	if _, err := i.ClearPresentment(ctx, b.ID, 4_999, "9F26"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	// card-not-present clearing (no field 55) is unchanged
	if got, err := i.Clear(ctx, b.ID, 4_999); err != nil || got.State != "CLEARED" || l.balance[1] != 100_000-2*4_999 {
		t.Fatalf("no chip data: %v %+v", err, got)
	}
}

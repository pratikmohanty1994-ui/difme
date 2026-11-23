package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeLedger struct {
	balance     map[int64]int64 // savings: balance (minor)
	holds       map[int64]int64 // hold ref -> amount
	holdAcct    map[int64]int64
	outstanding map[int64]int64 // loan -> principal outstanding
	next        int64
	down        bool
}

func newLedger() *fakeLedger {
	return &fakeLedger{balance: map[int64]int64{1: 100_000}, holds: map[int64]int64{}, holdAcct: map[int64]int64{}, outstanding: map[int64]int64{}}
}

var errDown = errors.New("ledger down")

func (l *fakeLedger) Available(_ context.Context, s int64) (int64, error) {
	if l.down {
		return 0, errDown
	}
	v := l.balance[s]
	for ref, amt := range l.holds {
		if l.holdAcct[ref] == s {
			v -= amt
		}
	}
	return v, nil
}
func (l *fakeLedger) Hold(_ context.Context, s, amt int64, _ string) (int64, error) {
	l.next++
	l.holds[l.next], l.holdAcct[l.next] = amt, s
	return l.next, nil
}
func (l *fakeLedger) Release(_ context.Context, _, ref int64) error { delete(l.holds, ref); return nil }
func (l *fakeLedger) Withdraw(_ context.Context, s, amt int64, _ string) error {
	l.balance[s] -= amt
	return nil
}
func (l *fakeLedger) Outstanding(_ context.Context, loan int64) (int64, error) {
	return l.outstanding[loan], nil
}
func (l *fakeLedger) Disburse(_ context.Context, loan, amt int64) error {
	l.outstanding[loan] += amt
	return nil
}

type fakeHSM struct{ pvv map[string]bool }

func (fakeHSM) CVV2(_ context.Context, pan, exp string) (string, error) { return "123", nil }
func (fakeHSM) VerifyCVV2(_ context.Context, _, _, c string) (bool, error) {
	return c == "123", nil
}
func (fakeHSM) DCVV2(context.Context, string) (string, error) { return "777", nil }
func (fakeHSM) VerifyDCVV2(_ context.Context, _, c string) (bool, error) {
	return c == "777", nil
}
func (fakeHSM) PINFromApp(_ context.Context, _, iso4 string) (string, error) {
	if !strings.HasPrefix(iso4, "4") {
		return "", errors.New("bad block")
	}
	if iso4 == "41111" {
		return "", ErrWeakPIN
	}
	return "Z" + iso4, nil
}
func (fakeHSM) GeneratePIN(context.Context, string) (string, string, error) {
	return "Z48264", "4-app", nil
}
func (fakeHSM) PVV(_ context.Context, _, block string) (string, error) {
	return "P" + block[len(block)-4:], nil
}
func (fakeHSM) VerifyPVV(_ context.Context, _, block, pvv string) (bool, error) {
	return "P"+block[len(block)-4:] == pvv, nil
}

func (fakeHSM) RevealPIN(_ context.Context, _, iso4, appKey string) (string, error) {
	if !strings.HasPrefix(appKey, "30") || len(appKey) < 40 {
		return "", ErrInvalid
	}
	return "jwe(" + iso4 + ")", nil
}

func setup(t *testing.T) (*Issuer, *fakeLedger) {
	l := newLedger()
	return New("437551", l, fakeHSM{}, NewMemStore()), l
}

func TestDebitHoldClearReverse(t *testing.T) {
	i, l := setup(t)
	ctx := context.Background()
	c, err := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "partner-1"})
	if err != nil || len(c.PANFull) != 16 || !strings.HasPrefix(c.PANFull, "437551") || c.CVV2 != "123" || luhn(c.PANFull[:15]) != c.PANFull {
		t.Fatalf("%v %+v", err, c)
	}
	a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 60_000, CVV2: "123", Merchant: "M1"})
	if a.Code != Approved || a.State != "HELD" {
		t.Fatalf("%+v", a)
	}
	if a2, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 50_000}); a2.Code != Insufficient {
		t.Fatalf("over the available balance (hold counted): %+v", a2)
	}
	if _, err := i.Clear(ctx, a.ID, 55_000); err != nil {
		t.Fatal(err)
	}
	if l.balance[1] != 45_000 || len(l.holds) != 0 {
		t.Fatalf("after clearing: balance %d holds %v", l.balance[1], l.holds)
	}
	b, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 40_000})
	if _, err := i.Reverse(ctx, b.ID); err != nil || len(l.holds) != 0 {
		t.Fatalf("reverse: %v %v", err, l.holds)
	}
	if _, err := i.Clear(ctx, b.ID, 1); err == nil {
		t.Error("a reversed authorisation was cleared")
	}
}

func TestCreditOpenToBuy(t *testing.T) {
	i, l := setup(t)
	ctx := context.Background()
	c, _ := i.Issue(ctx, IssueRequest{Product: Credit, Account: 9, LimitMinor: 500_000, Holder: "partner-2"})
	a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 300_000})
	if a.Code != Approved {
		t.Fatalf("%+v", a)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 250_000}); b.Code != Insufficient {
		t.Fatalf("open authorisations count against the limit: %+v", b)
	}
	_, _ = i.Clear(ctx, a.ID, 300_000)
	if l.outstanding[9] != 300_000 {
		t.Fatalf("disbursed %d", l.outstanding[9])
	}
	l.outstanding[9] -= 200_000 // repayment in Fineract restores the line
	if otb, _ := i.OpenToBuy(ctx, c.ID); otb != 400_000 {
		t.Fatalf("open to buy %d", otb)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 400_000}); b.Code != Approved {
		t.Fatalf("re-spend after repayment: %+v", b)
	}
}

func TestDeclinesAndCardSecurity(t *testing.T) {
	i, l := setup(t)
	ctx := context.Background()
	c, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p", Channels: []string{"app"}})
	cases := []struct {
		r    AuthRequest
		code string
	}{
		{AuthRequest{PAN: c.PANFull, AmountMinor: 100, CVV2: "999"}, DoNotHonour},
		{AuthRequest{PAN: c.PANFull, AmountMinor: 100, CVV2: "777"}, Approved}, // dynamic CVV2
		{AuthRequest{PAN: c.PANFull, AmountMinor: 100, Expiry: "2001"}, Expired},
		{AuthRequest{PAN: c.PANFull, AmountMinor: 100, PINBlock: "Z4111"}, WrongPIN}, // no PIN set yet
		{AuthRequest{PAN: "4375510000000001", AmountMinor: 100}, InvalidCard},
	}
	for _, k := range cases {
		if a, _ := i.Authorise(ctx, k.r); a.Code != k.code {
			t.Errorf("%+v: got %s want %s", k.r, a.Code, k.code)
		}
	}
	if err := i.SetPIN(ctx, c.ID, "41234"); err != nil {
		t.Fatal(err)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100, PINBlock: "Z41234"}); a.Code != Approved {
		t.Fatalf("right PIN: %+v", a)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100, PINBlock: "Z49999"}); a.Code != WrongPIN {
		t.Fatalf("wrong PIN: %+v", a)
	}
	if err := i.SetPIN(ctx, c.ID, "41111"); !errors.Is(err, ErrWeakPIN) {
		t.Errorf("weak PIN: %v", err)
	}
	if app, err := i.GeneratePIN(ctx, c.ID); err != nil || app != "4-app" {
		t.Fatalf("generate: %v %q", err, app)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100, PINBlock: "Z48264"}); a.Code != Approved {
		t.Fatalf("generated PIN: %+v", a)
	}
	if err := i.SetPIN(ctx, c.ID, "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad PIN block: %v", err)
	}
	_, _ = i.SetStatus(ctx, c.ID, "BLOCKED")
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100}); a.Code != DoNotHonour {
		t.Errorf("blocked: %s", a.Code)
	}
	_, _ = i.SetStatus(ctx, c.ID, "ACTIVE")
	l.down = true
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 100}); a.Code != SystemError {
		t.Errorf("ledger down: %s", a.Code)
	}
	if got, _ := i.CardByPAN(ctx, c.PANFull); got.Channels[0] != "app" || got.MaskedPAN != Mask(c.PANFull) {
		t.Errorf("ACS lookup: %+v", got)
	}
}

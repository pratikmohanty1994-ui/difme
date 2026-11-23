package issuer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

// expiryHSM: CVV2 depends on PAN and expiry, as the real one (psec-checked in services/hsm).
type expiryHSM struct{ fakeHSM }

func cvvOf(pan, exp string) string {
	h := sha256.Sum256([]byte(pan + exp))
	return fmt.Sprintf("%03d", int(h[0])<<8|int(h[1])%1000)[:3]
}
func (expiryHSM) CVV2(_ context.Context, pan, exp string) (string, error) {
	return cvvOf(pan, exp), nil
}
func (expiryHSM) VerifyCVV2(_ context.Context, pan, exp, c string) (bool, error) {
	return cvvOf(pan, exp) == c, nil
}

func renewSetup(t *testing.T, now time.Time) (*Issuer, *MemStore, *[]string) {
	st := NewMemStore()
	i := New("437551", newLedger(), expiryHSM{}, st)
	i.now = func() time.Time { return now }
	var audit []string
	i.Audit = func(_ context.Context, e string, attrs ...any) { audit = append(audit, e+fmt.Sprint(attrs...)) }
	return i, st, &audit
}

func TestRenewalSamePAN(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	i, _, audit := renewSetup(t, now)
	ctx := context.Background()
	old, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	_ = i.SetPIN(ctx, old.ID, "43917")
	i.now = func() time.Time { return now.AddDate(4, 11, 0) } // expiry due next month
	r, err := i.Renew(ctx, old.ID, RenewRequest{Reason: Renewal, GraceDays: 30})
	if err != nil || !r.SamePAN || r.PANFull != old.PANFull || r.ID != old.ID || r.Expiry == old.Expiry || r.CVV2 == old.CVV2 || r.PINRequired {
		t.Fatalf("%v %+v", err, r)
	}
	if r.PrevExpiry != old.Expiry || r.PrevValidUntil == nil {
		t.Fatalf("previous expiry not kept: %+v", r.Card)
	}
	auth := func(exp, cvv string) string {
		a, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, Expiry: exp, AmountMinor: 100, CVV2: cvv})
		return a.Code
	}
	if c := auth(old.Expiry, old.CVV2); c != Approved {
		t.Fatalf("old card in grace: %s", c)
	}
	if c := auth("", old.CVV2); c != Approved {
		t.Fatalf("old CVV2 without expiry in grace: %s", c)
	}
	if c := auth(old.Expiry, r.CVV2); c != DoNotHonour {
		t.Fatalf("new CVV2 with the old expiry: %s", c)
	}
	if c, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 100, PINBlock: "Z43917"}); c.Code != Approved {
		t.Fatalf("PIN kept: %+v", c)
	}
	if c := auth(r.Expiry, r.CVV2); c != Approved { // first use of the new card ends the old expiry
		t.Fatalf("new card: %s", c)
	}
	if c := auth(old.Expiry, old.CVV2); c != Expired {
		t.Fatalf("old card after the new one was used: %s", c)
	}
	got, _ := i.CardByPAN(ctx, old.PANFull)
	if got.Expiry != r.Expiry || got.PrevExpiry != "" {
		t.Fatalf("lookup by PAN (ACS, scheme-sim routing): %+v", got)
	}
	// renewing again in the same month is refused; a grace date passing ends the old expiry too
	if _, err := i.Renew(ctx, old.ID, RenewRequest{Reason: Renewal}); err == nil {
		t.Fatal("renewed twice to the same expiry")
	}
	if len(*audit) != 2 {
		t.Fatalf("audit: %q", *audit)
	}
}

func TestRenewalGraceDateSamePAN(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	i, _, _ := renewSetup(t, now)
	ctx := context.Background()
	old, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	i.now = func() time.Time { return now.AddDate(1, 0, 0) }
	r, _ := i.Renew(ctx, old.ID, RenewRequest{Reason: Replacement, GraceDays: 10})
	i.now = func() time.Time { return now.AddDate(1, 0, 11) }
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, Expiry: old.Expiry, AmountMinor: 100, CVV2: old.CVV2}); a.Code != Expired {
		t.Fatalf("old expiry after the grace date: %+v", a)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 100, CVV2: old.CVV2}); a.Code != DoNotHonour {
		t.Fatalf("old CVV2 after the grace date: %+v", a)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, Expiry: r.Expiry, AmountMinor: 100, CVV2: r.CVV2}); a.Code != Approved {
		t.Fatalf("new: %+v", a)
	}
}

func TestReissueNewPAN(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	i, st, _ := renewSetup(t, now)
	i.NewPANOnRenewal = map[string]bool{Credit: true}
	ctx := context.Background()
	old, _ := i.Issue(ctx, IssueRequest{Product: Credit, Account: 9, LimitMinor: 500_000, Holder: "p"})
	_ = st.PutStatement(ctx, Statement{CardID: old.ID, PeriodEnd: now, ClosingMinor: 1})
	a1, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 200_000, CVV2: old.CVV2})
	r, err := i.Renew(ctx, old.ID, RenewRequest{Reason: Renewal})
	if err != nil || r.SamePAN || r.PANFull == old.PANFull || r.Replaces != old.ID || !r.PINRequired || r.CVV2 != cvvOf(r.PANFull, r.Expiry) {
		t.Fatalf("%v %+v", err, r)
	}
	if o, _ := i.Card(ctx, old.ID); o.ReplacedBy != r.ID || o.ValidUntil == nil || o.Status != "ACTIVE" {
		t.Fatalf("old card: %+v", o)
	}
	if s, err := st.LastStatement(ctx, r.ID); err != nil || s.ClosingMinor != 1 {
		t.Fatalf("statement carried over: %v %+v", err, s)
	}
	// the credit line is shared: the old card's open authorisation counts on the new card
	if otb, _ := i.OpenToBuy(ctx, r.ID); otb != 300_000 {
		t.Fatalf("open to buy on the new card: %d", otb)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: r.PANFull, AmountMinor: 350_000}); b.Code != Insufficient {
		t.Fatalf("over the shared line: %+v", b)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 100, CVV2: old.CVV2}); b.Code != Approved {
		t.Fatalf("old card in grace: %+v", b)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: r.PANFull, Expiry: r.Expiry, AmountMinor: 100, CVV2: r.CVV2}); b.Code != Approved {
		t.Fatalf("new card: %+v", b)
	}
	if b, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 100, CVV2: old.CVV2}); b.Code != DoNotHonour {
		t.Fatalf("old card after the new card's first use: %+v", b)
	}
	if o, _ := i.Card(ctx, old.ID); o.Status != "REPLACED" {
		t.Fatalf("old status %s", o.Status)
	}
	// the old card's held authorisation still clears onto the line
	if _, err := i.Clear(ctx, a1.ID, 200_000); err != nil {
		t.Fatal(err)
	}
	// both PANs resolve (ACS lookup / scheme-sim routing); the old one is REPLACED
	if c, _ := i.CardByPAN(ctx, r.PANFull); c.ID != r.ID {
		t.Fatal("new PAN lookup")
	}
	if _, err := i.Renew(ctx, old.ID, RenewRequest{Reason: Renewal}); err == nil {
		t.Fatal("renewed a replaced card")
	}
	// both cards stay listed; RunBilling skips the one with ReplacedBy
	ids, _ := st.CreditCards(ctx)
	if len(ids) != 2 {
		t.Fatalf("credit cards %v", ids)
	}
}

func TestReissueLostStolenAndGraceDate(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	i, _, _ := renewSetup(t, now)
	ctx := context.Background()
	old, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	r, err := i.Renew(ctx, old.ID, RenewRequest{Reason: LostStolen})
	if err != nil || r.SamePAN || r.PANFull == old.PANFull {
		t.Fatalf("lost/stolen always gets a new PAN: %v %+v", err, r)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: old.PANFull, AmountMinor: 100}); a.Code != DoNotHonour {
		t.Fatalf("lost card: %+v", a)
	}
	// replacement with a new PAN: the old card stops at the grace date even unused
	i.NewPANOnRenewal = map[string]bool{Debit: true}
	r2, _ := i.Renew(ctx, r.ID, RenewRequest{Reason: Replacement, GraceDays: 5})
	i.now = func() time.Time { return now.AddDate(0, 0, 6) }
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: r.PANFull, AmountMinor: 100}); a.Code != Expired {
		t.Fatalf("after grace date: %+v", a)
	}
	if a, _ := i.Authorise(ctx, AuthRequest{PAN: r2.PANFull, AmountMinor: 100}); a.Code != Approved {
		t.Fatalf("replacement: %+v", a)
	}
	for _, bad := range []RenewRequest{{Reason: "X"}, {Reason: Renewal, GraceDays: 400}} {
		if _, err := i.Renew(ctx, r2.ID, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	_, _ = i.SetStatus(ctx, r2.ID, "BLOCKED")
	if _, err := i.Renew(ctx, r2.ID, RenewRequest{Reason: Renewal}); err == nil {
		t.Error("renewal of a blocked card")
	}
}

package issuer

import (
	"context"
	"testing"
	"time"
)

// creditLedger adds statement data to the fake ledger.
type creditLedger struct {
	*fakeLedger
	txns     []LedgerTxn
	interest int64
	waived   int64
}

func (c *creditLedger) Transactions(context.Context, int64) ([]LedgerTxn, error) { return c.txns, nil }
func (c *creditLedger) Balance(_ context.Context, loan int64) (int64, int64, error) {
	return c.outstanding[loan], c.interest, nil
}
func (c *creditLedger) WaiveInterest(_ context.Context, _ int64, amt int64) error {
	c.interest -= amt
	c.waived += amt
	return nil
}

func TestStatementAndGrace(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.Local)
	l := &creditLedger{fakeLedger: newLedger()}
	i := New("437551", l, fakeHSM{}, NewMemStore())
	i.now = func() time.Time { return now }
	c, _ := i.Issue(ctx, IssueRequest{Product: Credit, Account: 5, LimitMinor: 1_000_000, Holder: "p"})
	a, _ := i.Authorise(ctx, AuthRequest{PAN: c.PANFull, AmountMinor: 400_000})
	_, _ = i.Clear(ctx, a.ID, 400_000)
	l.txns = []LedgerTxn{{Date: now.AddDate(0, 0, -5), Type: "DISBURSEMENT", AmountMinor: 400_000},
		{Date: now.AddDate(0, 0, -40), Type: "DISBURSEMENT", AmountMinor: 1}} // previous cycle: not on this statement
	l.interest = 6_000
	s, err := i.MakeStatement(ctx, c.ID, 30)
	if err != nil || s.PurchasesMinor != 400_000 || s.ClosingMinor != 406_000 || s.MinimumDueMinor != 20_300 || !s.DueDate.Equal(now.AddDate(0, 0, 20)) {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := i.SettleGrace(ctx, c.ID); err == nil {
		t.Fatal("grace settled before the due date")
	}
	// paid in full within the due date: interest waived
	l.txns = append(l.txns, LedgerTxn{Date: now.AddDate(0, 0, 10), Type: "REPAYMENT", AmountMinor: 400_000})
	now = now.AddDate(0, 0, 21)
	g, err := i.SettleGrace(ctx, c.ID)
	if err != nil || g.Grace != "GRANTED" || l.waived != 6_000 {
		t.Fatalf("%v %+v waived=%d", err, g, l.waived)
	}
	// next cycle, only the minimum paid: grace lost, interest stands
	l.outstanding[5], l.interest, l.waived = 300_000, 4_500, 0
	l.txns = append(l.txns, LedgerTxn{Date: now.AddDate(0, 0, -2), Type: "DISBURSEMENT", AmountMinor: 300_000})
	s2, _ := i.MakeStatement(ctx, c.ID, 30)
	if !s2.PeriodStart.Equal(s.PeriodEnd) || s2.MinimumDueMinor != 15_225 {
		t.Fatalf("second statement: %+v", s2)
	}
	l.txns = append(l.txns, LedgerTxn{Date: now.AddDate(0, 0, 5), Type: "REPAYMENT", AmountMinor: 15_225})
	now = now.AddDate(0, 0, 21)
	if g2, _ := i.SettleGrace(ctx, c.ID); g2.Grace != "LOST" || l.waived != 0 {
		t.Fatalf("minimum paid: %+v waived=%d", g2, l.waived)
	}
	// small balance: minimum due is the whole balance
	l.outstanding[5], l.interest = 5_000, 0
	if s3, _ := i.MakeStatement(ctx, c.ID, 30); s3.MinimumDueMinor != 5_000 {
		t.Fatalf("small balance minimum: %+v", s3)
	}
	// debit cards have no statements here
	d, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	if _, err := i.MakeStatement(ctx, d.ID, 30); err == nil {
		t.Error("statement for a debit card")
	}
}

func TestRunBilling(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.Local)
	l := &creditLedger{fakeLedger: newLedger()}
	i := New("437551", l, fakeHSM{}, NewMemStore())
	i.now = func() time.Time { return now }
	c, _ := i.Issue(ctx, IssueRequest{Product: Credit, Account: 5, LimitMinor: 1_000_000, Holder: "p"})
	if m, _, _ := i.RunBilling(ctx); m != 0 {
		t.Fatal("statement before the first cycle ended")
	}
	now = now.AddDate(0, 0, 30)
	l.outstanding[5] = 100_000
	if m, _, _ := i.RunBilling(ctx); m != 1 {
		t.Fatal("no statement after 30 days")
	}
	now = now.AddDate(0, 0, 21)
	l.txns = []LedgerTxn{{Date: now.AddDate(0, 0, -3), Type: "REPAYMENT", AmountMinor: 100_000}}
	if _, s, _ := i.RunBilling(ctx); s != 1 {
		t.Fatal("grace not settled after the due date")
	}
	if st, _ := i.store.LastStatement(ctx, c.ID); st.Grace != "GRANTED" {
		t.Fatalf("%+v", st)
	}
}

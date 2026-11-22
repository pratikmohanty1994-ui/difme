package issuer

import (
	"context"
	"fmt"
	"time"
)

// LedgerTxn is a posted credit-line transaction from the ledger.
type LedgerTxn struct {
	Date        time.Time
	Type        string // DISBURSEMENT (purchases), REPAYMENT, INTEREST, CHARGEBACK, …
	AmountMinor int64
}

// CreditLedger is what statements need from the ledger beyond Ledger.
type CreditLedger interface {
	Transactions(ctx context.Context, loan int64) ([]LedgerTxn, error)
	Balance(ctx context.Context, loan int64) (principal, interest int64, err error)
	WaiveInterest(ctx context.Context, loan int64, amountMinor int64) error
}

// Statement is one billing cycle of a credit card.
type Statement struct {
	CardID          string    `json:"cardId"`
	PeriodStart     time.Time `json:"periodStart"`
	PeriodEnd       time.Time `json:"periodEnd"`
	PurchasesMinor  int64     `json:"purchasesMinor"`
	PaymentsMinor   int64     `json:"paymentsMinor"`
	PrincipalMinor  int64     `json:"principalMinor"`
	InterestMinor   int64     `json:"interestMinor"`
	ClosingMinor    int64     `json:"closingMinor"`
	MinimumDueMinor int64     `json:"minimumDueMinor"`
	DueDate         time.Time `json:"dueDate"`
	Grace           string    `json:"grace,omitempty"` // "" until the due date; then GRANTED (interest waived) or LOST
}

// Statement rules (ADR-025): minimum due 5% of the closing balance, at least INR 100 (or the whole balance when
// smaller), due 20 days after the statement date; interest-free grace when the statement is paid in full by then.
const (
	minDuePercent   = 5
	minDueFloor     = 10_000
	dueAfterDays    = 20
	defaultCycleLen = 30
)

func (i *Issuer) credit() (CreditLedger, error) {
	cl, ok := i.ledger.(CreditLedger)
	if !ok {
		return nil, fmt.Errorf("ledger without credit statements")
	}
	return cl, nil
}

// MakeStatement closes the cycle ending now for a credit card and stores the statement.
func (i *Issuer) MakeStatement(ctx context.Context, cardID string, cycleDays int) (Statement, error) {
	c, err := i.store.Card(ctx, cardID)
	if err != nil {
		return Statement{}, err
	}
	if c.Product != Credit {
		return Statement{}, fmt.Errorf("%w: statements are for credit cards", ErrInvalid)
	}
	cl, err := i.credit()
	if err != nil {
		return Statement{}, err
	}
	if cycleDays <= 0 {
		cycleDays = defaultCycleLen
	}
	end := i.now()
	start := end.AddDate(0, 0, -cycleDays)
	if prev, err := i.store.LastStatement(ctx, cardID); err == nil && prev.PeriodEnd.After(start) {
		start = prev.PeriodEnd
	}
	txns, err := cl.Transactions(ctx, c.Account)
	if err != nil {
		return Statement{}, err
	}
	s := Statement{CardID: cardID, PeriodStart: start, PeriodEnd: end, DueDate: end.AddDate(0, 0, dueAfterDays)}
	for _, t := range txns {
		if t.Date.Before(start) || t.Date.After(end) {
			continue
		}
		switch t.Type {
		case "DISBURSEMENT":
			s.PurchasesMinor += t.AmountMinor
		case "REPAYMENT":
			s.PaymentsMinor += t.AmountMinor
		}
	}
	if s.PrincipalMinor, s.InterestMinor, err = cl.Balance(ctx, c.Account); err != nil {
		return Statement{}, err
	}
	s.ClosingMinor = s.PrincipalMinor + s.InterestMinor
	s.MinimumDueMinor = min(s.ClosingMinor, max(s.ClosingMinor*minDuePercent/100, minDueFloor))
	return s, i.store.PutStatement(ctx, s)
}

// SettleGrace runs at (or after) the due date of the card's latest statement: paid in full → the statement's
// interest is waived in the ledger (GRANTED); otherwise the interest stands (LOST).
func (i *Issuer) SettleGrace(ctx context.Context, cardID string) (Statement, error) {
	s, err := i.store.LastStatement(ctx, cardID)
	if err != nil {
		return Statement{}, err
	}
	if s.Grace != "" || i.now().Before(s.DueDate) {
		return s, fmt.Errorf("%w: grace already settled or not yet due", ErrInvalid)
	}
	c, err := i.store.Card(ctx, cardID)
	if err != nil {
		return Statement{}, err
	}
	cl, err := i.credit()
	if err != nil {
		return Statement{}, err
	}
	txns, err := cl.Transactions(ctx, c.Account)
	if err != nil {
		return Statement{}, err
	}
	var paid int64
	for _, t := range txns {
		if t.Type == "REPAYMENT" && t.Date.After(s.PeriodEnd) && !t.Date.After(s.DueDate) {
			paid += t.AmountMinor
		}
	}
	s.Grace = "LOST"
	if paid >= s.ClosingMinor-s.InterestMinor && s.InterestMinor > 0 { // principal of the statement paid in full
		_, interest, err := cl.Balance(ctx, c.Account)
		if err != nil {
			return Statement{}, err
		}
		if w := min(interest, s.InterestMinor); w > 0 {
			if err := cl.WaiveInterest(ctx, c.Account, w); err != nil {
				return Statement{}, err
			}
		}
		s.Grace = "GRANTED"
	} else if paid >= s.ClosingMinor-s.InterestMinor {
		s.Grace = "GRANTED"
	}
	return s, i.store.PutStatement(ctx, s)
}

// RunBilling is the daily billing job: a statement for every credit card whose cycle has ended (first one 30 days
// after issue), and grace settled for statements past their due date. Returns how many statements and settlements.
func (i *Issuer) RunBilling(ctx context.Context) (made, settled int, err error) {
	ids, err := i.store.CreditCards(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		last, lerr := i.store.LastStatement(ctx, id)
		if lerr == nil && last.Grace == "" && !i.now().Before(last.DueDate) {
			if _, err := i.SettleGrace(ctx, id); err == nil {
				settled++
			}
		}
		since := time.Time{}
		if lerr == nil {
			since = last.PeriodEnd
		} else if c, err := i.store.Card(ctx, id); err == nil {
			since = c.CreatedAt
		}
		if !i.now().Before(since.AddDate(0, 0, defaultCycleLen)) {
			if _, err := i.MakeStatement(ctx, id, defaultCycleLen); err == nil {
				made++
			}
		}
	}
	return made, settled, nil
}

package scheme

import (
	"fmt"
	"testing"
	"time"

	"github.com/moov-io/iso8583"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/tokens"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

var stan = 0

// authReq builds a 0100 for number (card or token) at a merchant, with an optional field 48 (cryptogram).
func authReq(t *testing.T, number, merchant string, amount int64, f48 string) *iso8583.Message {
	t.Helper()
	stan++
	m := iso8583.NewMessage(wire.Spec)
	m.MTI("0100")
	for id, v := range map[int]string{2: number, 3: "000000", 4: fmt.Sprintf("%012d", amount), 11: fmt.Sprintf("%06d", stan),
		41: "TERM0001", 42: merchant, 49: "356"} {
		if err := m.Field(id, v); err != nil {
			t.Fatal(err)
		}
	}
	if f48 != "" {
		if err := m.Field(48, f48); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func send(t *testing.T, n *Network, m *iso8583.Message) (code, pan string) {
	t.Helper()
	r, err := n.Handle(m)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Get(r, 39), wire.Get(r, 2)
}

func newNet(t *testing.T) *Network {
	n := New()
	if err := n.PutCard(Card{PAN: "4375510000000001", Expiry: time.Now().AddDate(2, 0, 0).Format("0601"), LimitMinor: 1_000_000, Status: "ACTIVE"}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTokenPaymentIsApprovedAgainstTheCardAndKeepsTheToken(t *testing.T) {
	n := newNet(t)
	tok, err := n.Tokens.Provision("4375510000000001", "MERCHANT01")
	if err != nil || !tokens.IsToken(tok.Number) || tok.Number == tok.PAN {
		t.Fatalf("provision: %v %+v", err, tok)
	}
	cg, _ := n.Tokens.Cryptogram(tok.Number, "MERCHANT01", 50_000)
	code, pan := send(t, n, authReq(t, tok.Number, "MERCHANT01", 50_000, cg))
	if code != Approved || pan != tok.Number {
		t.Fatalf("got %s for %s; want 00 with the token in field 2", code, pan)
	}
	if c, _ := n.Card("4375510000000001"); c.OutstandingMinor != 50_000 {
		t.Fatalf("hold on the card: %d", c.OutstandingMinor)
	}
}

func TestTokenRulesDeclineAtTheNetwork(t *testing.T) {
	n := newNet(t)
	tok, _ := n.Tokens.Provision("4375510000000001", "MERCHANT01")
	cg, _ := n.Tokens.Cryptogram(tok.Number, "MERCHANT01", 1000)

	if code, _ := send(t, n, authReq(t, tok.Number, "MERCHANT01", 1000, "")); code != DoNotHonour {
		t.Errorf("no cryptogram: %s, want %s", code, DoNotHonour)
	}
	if code, _ := send(t, n, authReq(t, tok.Number, "MERCHANT01", 2000, cg)); code != DoNotHonour {
		t.Errorf("cryptogram for another amount: %s", code)
	}
	if code, _ := send(t, n, authReq(t, tok.Number, "OTHERSHOP1", 1000, cg)); code != Restricted {
		t.Errorf("token at another merchant: %s, want %s", code, Restricted)
	}
	if code, _ := send(t, n, authReq(t, tok.Number, "MERCHANT01", 1000, cg)); code != Approved {
		t.Fatalf("the genuine payment: %s", code)
	}
	if code, _ := send(t, n, authReq(t, tok.Number, "MERCHANT01", 1000, cg)); code != DoNotHonour {
		t.Errorf("replayed cryptogram: %s", code)
	}
	if code, _ := send(t, n, authReq(t, tokens.TokenBIN+"0000000009", "MERCHANT01", 1000, cg)); code != InvalidCard {
		t.Errorf("unknown token: %s, want %s", code, InvalidCard)
	}
}

func TestTokenLifecycle(t *testing.T) {
	n := newNet(t)
	tok, _ := n.Tokens.Provision("4375510000000001", "MERCHANT01")
	_ = n.Tokens.SetStatus(tok.Number, "SUSPENDED")
	if _, err := n.Tokens.Cryptogram(tok.Number, "MERCHANT01", 1000); err != tokens.ErrNotActive {
		t.Fatalf("suspended token got a cryptogram: %v", err)
	}
	_ = n.Tokens.SetStatus(tok.Number, "ACTIVE")
	// card replaced (lost/stolen): the token now pays against the new card
	if err := n.PutCard(Card{PAN: "4375510000000019", Expiry: time.Now().AddDate(3, 0, 0).Format("0601"), LimitMinor: 500_000, Status: "ACTIVE"}); err != nil {
		t.Fatal(err)
	}
	if moved := n.Tokens.ReplaceCard("4375510000000001", "4375510000000019"); moved != 1 {
		t.Fatalf("moved %d tokens", moved)
	}
	cg, _ := n.Tokens.Cryptogram(tok.Number, "MERCHANT01", 7000)
	if code, _ := send(t, n, authReq(t, tok.Number, "MERCHANT01", 7000, cg)); code != Approved {
		t.Fatalf("after replacement: %s", code)
	}
	if c, _ := n.Card("4375510000000019"); c.OutstandingMinor != 7000 {
		t.Fatalf("hold on the new card: %d", c.OutstandingMinor)
	}
	_ = n.Tokens.SetStatus(tok.Number, "DELETED")
	if err := n.Tokens.SetStatus(tok.Number, "ACTIVE"); err == nil {
		t.Fatal("a deleted token came back")
	}
}

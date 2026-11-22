package scheme

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/moov-io/iso8583"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

type fakeIssuer struct {
	got      []IssuerRequest
	code     string
	cleared  []string
	reversed []string
	down     bool
}

func (f *fakeIssuer) Authorise(_ context.Context, r IssuerRequest) (string, string, error) {
	if f.down {
		return "", "", errors.New("down")
	}
	f.got = append(f.got, r)
	return f.code, fmt.Sprintf("auth-%d", len(f.got)), nil
}
func (f *fakeIssuer) Clear(_ context.Context, id string, _ int64) error {
	f.cleared = append(f.cleared, id)
	return nil
}
func (f *fakeIssuer) Reverse(_ context.Context, id string) error {
	f.reversed = append(f.reversed, id)
	return nil
}

func msg(t *testing.T, mti, pan string, amount int64, extra map[int]string) *iso8583.Message {
	stan++
	m := iso8583.NewMessage(wire.Spec)
	m.MTI(mti)
	f := map[int]string{2: pan, 3: "000000", 4: fmt.Sprintf("%012d", amount), 11: fmt.Sprintf("%06d", stan), 41: "TERM0001", 42: "MERCHANT01", 49: "356"}
	for k, v := range extra {
		f[k] = v
	}
	for id, v := range f {
		if err := m.Field(id, v); err != nil {
			t.Fatal(id, err)
		}
	}
	return m
}

func TestIssuerHostDecidesForItsCards(t *testing.T) {
	n := New()
	is := &fakeIssuer{code: Approved}
	n.Issuer = is
	pan := "4375519999999995"
	r, _ := n.Handle(msg(t, "0100", pan, 5000, map[int]string{48: "CVV2:123", 52: "\x01\x02\x03\x04\x05\x06\x07\x08", 14: "3012"}))
	if wire.Get(r, 39) != Approved || len(is.got) != 1 || is.got[0].CVV2 != "123" || is.got[0].PINBlock != "0102030405060708" || is.got[0].Expiry != "3012" {
		t.Fatalf("%s %+v", wire.Get(r, 39), is.got)
	}
	if len(is.cleared) != 0 {
		t.Fatal("an authorisation (0100) was cleared")
	}
	rrn := wire.Get(r, 37)
	rev := msg(t, "0400", pan, 5000, map[int]string{37: rrn})
	if r, _ := n.Handle(rev); wire.Get(r, 39) != Approved || len(is.reversed) != 1 || is.reversed[0] != "auth-1" {
		t.Fatalf("reversal: %s %v", wire.Get(r, 39), is.reversed)
	}
	if r, _ := n.Handle(msg(t, "0200", pan, 700, nil)); wire.Get(r, 39) != Approved || len(is.cleared) != 1 {
		t.Fatalf("purchase is cleared at once: %v", is.cleared)
	}
	is.code = "51"
	if r, _ := n.Handle(msg(t, "0100", pan, 99999, nil)); wire.Get(r, 39) != "51" {
		t.Fatalf("issuer decline code: %s", wire.Get(r, 39))
	}
	is.down = true
	if r, _ := n.Handle(msg(t, "0100", pan, 100, nil)); wire.Get(r, 39) != IssuerDown {
		t.Fatalf("issuer down: %s", wire.Get(r, 39))
	}
}

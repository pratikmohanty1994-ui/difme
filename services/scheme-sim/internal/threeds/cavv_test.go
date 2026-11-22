package threeds_test

import (
	"context"
	"testing"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds/threedstest"
)

// The test stand-in reproduces the published Visa vector and the psec / services/hsm values.
func TestStandInMatchesReferences(t *testing.T) {
	k := threedstest.TestCVK
	for _, c := range []struct{ pan, four, three, want string }{
		{"4123456789012345", "8701", "101", "561"}, // published Visa CVV vector
		{"4375510000000001", "3012", "000", "523"}, // psec CVV2
		{"4375510000000001", "1234", "000", "675"}, // psec CAVV (upn 1234, authrc 0, sfarc 00)
		{"4895370000000013", "9876", "715", "062"}, // psec CAVV
	} {
		if got := threedstest.CVV(k, c.pan, c.four, c.three); got != c.want {
			t.Errorf("%v: got %s", c, got)
		}
	}
}

func TestCAVVRoundTripAndTampering(t *testing.T) {
	h := threedstest.New()
	ctx := context.Background()
	v, c, err := threeds.Build(ctx, h, "4375510000000001", threeds.ResultChallenge, 1)
	if err != nil || len(v) != 28 {
		t.Fatalf("%v %q", err, v)
	}
	got, err := threeds.Verify(ctx, h, "4375510000000001", v)
	if err != nil || got != c || got.ECI != 5 {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if _, err := threeds.Verify(ctx, h, "4375510000000019", v); err != threeds.ErrCryptogram {
		t.Errorf("another card: %v", err)
	}
	// raise a frictionless result to a challenge result without the key: cryptogram fails
	fr, _, _ := threeds.Build(ctx, h, "4375510000000001", threeds.ResultFriction, 0)
	d, _ := threeds.Decode(fr)
	d.Result, d.SecondFactor = threeds.ResultChallenge, 1
	if _, err := threeds.Verify(ctx, h, "4375510000000001", d.Encode()); err != threeds.ErrCryptogram {
		t.Errorf("forged result code: %v", err)
	}
	// an ECI that does not match the result is a format error
	d, _ = threeds.Decode(fr)
	d.ECI = 6
	if _, err := threeds.Decode(d.Encode()); err != threeds.ErrFormat {
		t.Errorf("wrong ECI: %v", err)
	}
	for _, bad := range []string{"", "AAAA", "BwEBAQZ1EjQAAAAAAAAAAAAAAAAAAAA="} {
		if _, err := threeds.Decode(bad); err != threeds.ErrFormat {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

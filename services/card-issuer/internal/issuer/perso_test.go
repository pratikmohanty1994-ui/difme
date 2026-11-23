package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPersoFileRequest(t *testing.T) {
	i, _ := setup(t)
	var audit []string
	i.Audit = func(_ context.Context, e string, _ ...any) { audit = append(audit, e) }
	ctx := context.Background()
	a, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "p"})
	b, _ := i.Issue(ctx, IssueRequest{Product: Debit, Account: 1, Holder: "q"})
	if _, err := i.Perso(ctx, []string{a.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("without the issuer certificate: %v", err)
	}
	ic, err := ParseIssuerCert("92:AABB::03")
	if err != nil {
		t.Fatal(err)
	}
	i.PersoIssuerCert = ic
	f, err := i.Perso(ctx, []string{a.ID, b.ID})
	if err != nil || !strings.Contains(f, a.PANFull+":00:"+a.Expiry) || !strings.Contains(f, "ISSUER=437551|ISSUER_CERT=AABB") {
		t.Fatalf("%v %q", err, f)
	}
	_, _ = i.SetStatus(ctx, b.ID, "BLOCKED")
	if _, err := i.Perso(ctx, []string{a.ID, b.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("blocked card in a bureau file: %v", err)
	}
	if _, err := i.Perso(ctx, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty list")
	}
	for _, bad := range []string{"", "92:AABB:03", "92:XX::03", "92:::03"} {
		if _, err := ParseIssuerCert(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(audit) != 1 || audit[0] != "perso_file" {
		t.Errorf("audit %v", audit)
	}
}

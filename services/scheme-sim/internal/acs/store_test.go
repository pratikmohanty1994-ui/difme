package acs_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
)

// The Postgres tests run against a real database when ACS_TEST_DATABASE_URL is set (e.g.
// postgres://fineract:fin@127.0.0.1:5433/acs_test); otherwise they are skipped. They empty the acs_challenge table.
func pgURL(t *testing.T) string {
	u := os.Getenv("ACS_TEST_DATABASE_URL")
	if u == "" {
		t.Skip("ACS_TEST_DATABASE_URL not set (Postgres store test)")
	}
	return u
}

func pgStore(t *testing.T) *acs.PostgresStore {
	u := pgURL(t)
	ctx := context.Background()
	s, err := acs.NewPostgresStore(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	c, err := pgx.Connect(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "DELETE FROM acs_challenge"); err != nil {
		t.Fatal(err)
	}
	return s
}

func stores(t *testing.T) map[string]func(t *testing.T) acs.ChallengeStore {
	return map[string]func(t *testing.T) acs.ChallengeStore{
		"memory":   func(*testing.T) acs.ChallengeStore { return acs.NewMemoryStore() },
		"postgres": func(t *testing.T) acs.ChallengeStore { return pgStore(t) },
	}
}

func TestChallengeStoreContract(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s, ctx := mk(t), context.Background()
			exp := time.Date(2026, 11, 22, 10, 0, 0, 123456789, time.UTC)
			ch := &acs.ChallengeState{AReq: areq(pan, 1000), Card: acs.Card{Expiry: "3012", Status: "ACTIVE", Channels: []string{"sms"}},
				Version: "2.3.1", ACSTransID: "t-1", Step: "otp", OTPMAC: []byte{1, 2, 3}, Expires: exp}
			if err := s.Create(ctx, ch); err != nil || ch.Rev != 1 {
				t.Fatalf("create: %v rev %d", err, ch.Rev)
			}
			if err := s.Create(ctx, &acs.ChallengeState{ACSTransID: "t-1", Expires: exp}); !errors.Is(err, acs.ErrConflict) {
				t.Fatalf("duplicate create: %v", err)
			}
			got, err := s.Get(ctx, "t-1")
			if err != nil || got.Rev != 1 || got.Step != "otp" || !slices.Equal(got.OTPMAC, []byte{1, 2, 3}) || !got.Expires.Equal(exp) ||
				got.AReq.AcctNumber != pan || got.Card.Channels[0] != "sms" {
				t.Fatalf("get: %v %+v", err, got)
			}
			stale := *got
			got.Attempts = 1
			if err := s.Update(ctx, got); err != nil || got.Rev != 2 {
				t.Fatalf("update: %v rev %d", err, got.Rev)
			}
			if err := s.Update(ctx, &stale); !errors.Is(err, acs.ErrConflict) {
				t.Fatalf("stale update: %v", err)
			}
			if err := s.Delete(ctx, "t-1", 1); !errors.Is(err, acs.ErrConflict) {
				t.Fatalf("stale delete: %v", err)
			}
			if again, _ := s.Get(ctx, "t-1"); again.Attempts != 1 || again.Rev != 2 {
				t.Fatalf("after update: %+v", again)
			}
			_ = s.Create(ctx, &acs.ChallengeState{ACSTransID: "t-0", Step: "oob", Expires: exp})
			if all, err := s.List(ctx); err != nil || len(all) != 2 || all[0].ACSTransID != "t-0" || all[1].Rev != 2 {
				t.Fatalf("list: %v %d", err, len(all))
			}
			if err := s.Delete(ctx, "t-1", 2); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, "t-1"); !errors.Is(err, acs.ErrNoChallenge) {
				t.Fatalf("get after delete: %v", err)
			}
			if err := s.Delete(ctx, "t-1", 2); !errors.Is(err, acs.ErrNoChallenge) {
				t.Fatalf("delete twice: %v", err)
			}
			if err := s.Update(ctx, got); !errors.Is(err, acs.ErrNoChallenge) {
				t.Fatalf("update after delete: %v", err)
			}
		})
	}
}

func sdkKey(t *testing.T) *acs.JWK {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := k.PublicKey().Bytes()
	e := base64.RawURLEncoding
	return &acs.JWK{Kty: "EC", Crv: "P-256", X: e.EncodeToString(b[1:33]), Y: e.EncodeToString(b[33:65])}
}

// jweFor is an app-channel CReq whose header names the challenge (the body does not matter here).
func jweFor(acsTransID string) string {
	h, _ := json.Marshal(map[string]string{"alg": "dir", "enc": "A128GCM", "kid": acsTransID})
	return base64.RawURLEncoding.EncodeToString(h) + "..AAAA.AAAA.AAAA"
}

// A restarted ACS (a new process on the same store) carries on a passcode challenge, attempts included; app-channel
// challenges, whose session keys lived only in the old process, end with transStatus U — at start-up for its own
// (Recover), on the next CReq for another instance's (AppChallenge).
func TestChallengesAcrossRestart(t *testing.T) {
	for name, mk := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx, store := context.Background(), mk(t)
			w := newWorld(t, acs.Alert)
			signer, err := acs.DevSigner()
			if err != nil {
				t.Fatal(err)
			}
			start := func(instance string) *acs.ACS {
				return acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "https://acs.example/3ds/creq", PayerKey: []byte("test-key-0123456789"),
					Signer: signer, Store: store, Instance: instance}, w.cmsClient(), w.frm, w.hsm, w.otp, w.oob, w.rreqs)
			}
			before := start("acs-0")
			app := func(a *acs.ACS) string {
				q := areq(pan, 1000)
				q.DeviceChannel, q.SDKEphemPubKey, q.SDKReferenceNumber, q.SDKTransID = "01", sdkKey(t), "DIFME-TEST-SDK-REF-1", "sdk-1"
				res, err := a.Authenticate(ctx, q)
				if err != nil || res.TransStatus != "C" || res.ACSSignedContent == "" {
					t.Fatalf("app AReq: %v %+v", err, res)
				}
				return res.ACSTransID
			}
			appOwn := app(before)
			appOther := app(start("acs-1"))
			otpRes, err := before.Authenticate(ctx, areq(pan, 1000)) // last: its passcode is the one in w.otp
			if err != nil || otpRes.TransStatus != "C" {
				t.Fatalf("%v %+v", err, otpRes)
			}
			creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: otpRes.ACSTransID, ChallengeDataEntry: "x"}
			if cres, err := before.Challenge(ctx, creq); err != nil || cres.ChallengeCompletionInd != "N" {
				t.Fatalf("wrong code: %v %+v", err, cres)
			}
			after := start("acs-0") // restart
			if n, err := after.Recover(ctx); err != nil || n != 1 {
				t.Fatalf("recover: %d %v", n, err)
			}
			if len(w.rreqs.got) != 1 || w.rreqs.got[0].ACSTransID != appOwn || w.rreqs.got[0].TransStatus != "U" || w.rreqs.got[0].TransStatusReason != acs.ReasonSecurity {
				t.Fatalf("RReq for the lost app challenge: %+v", w.rreqs.got)
			}
			if _, err := after.AppChallenge(ctx, jweFor(appOther)); !errors.Is(err, acs.ErrBadRequest) {
				t.Fatalf("app challenge without its key: %v", err)
			}
			if len(w.rreqs.got) != 2 || w.rreqs.got[1].ACSTransID != appOther || w.rreqs.got[1].TransStatus != "U" {
				t.Fatalf("RReq for the other instance's app challenge: %+v", w.rreqs.got)
			}
			// the passcode challenge carries on with its attempt count
			creq.ChallengeDataEntry = w.otp.last
			cres, err := after.Challenge(ctx, creq)
			if err != nil || cres.TransStatus != "Y" {
				t.Fatalf("after restart: %v %+v", err, cres)
			}
			if rr := w.rreqs.got[2]; rr.TransStatus != "Y" || rr.InteractionCounter != "02" || rr.AuthenticationValue == "" {
				t.Fatalf("RReq: %+v", rr)
			}
			if all, _ := store.List(ctx); len(all) != 0 {
				t.Fatalf("store not empty: %d", len(all))
			}
		})
	}
}

// What the Postgres store writes: the challenge document, with the passcode only as its HMAC and no app-channel key.
func TestPostgresDocumentHasNoKeyMaterial(t *testing.T) {
	store, ctx := pgStore(t), context.Background()
	w := newWorld(t, acs.Alert)
	signer, _ := acs.DevSigner()
	a := acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "https://acs.example/3ds/creq", PayerKey: []byte("test-key-0123456789"),
		Signer: signer, Store: store, Instance: "acs-0"}, w.cmsClient(), w.frm, w.hsm, w.otp, w.oob, w.rreqs)
	q := areq(pan, 1000)
	q.DeviceChannel, q.SDKEphemPubKey, q.SDKReferenceNumber = "01", sdkKey(t), "REF"
	res, err := a.Authenticate(ctx, q)
	if err != nil || res.TransStatus != "C" {
		t.Fatalf("%v %+v", err, res)
	}
	c, err := pgx.Connect(ctx, pgURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var doc map[string]any
	if err := c.QueryRow(ctx, "SELECT doc FROM acs_challenge WHERE acs_trans_id = $1", res.ACSTransID).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range doc {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"acsTransID", "app", "areq", "attempts", "card", "expires", "messageVersion", "otpMAC", "owner", "step"}
	if !slices.Equal(keys, want) {
		t.Fatalf("document fields %v, want %v", keys, want)
	}
	raw, _ := json.Marshal(doc)
	if otp := w.otp.last; otp == "" || strings.Contains(string(raw), `"`+otp+`"`) {
		t.Fatalf("passcode in clear in the document")
	}
}

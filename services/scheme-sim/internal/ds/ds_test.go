package ds_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/ds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds/threedstest"
)

const pan = "4375510000000001"

type cards struct{}

func (cards) Card(_ context.Context, p string) (acs.Card, bool, error) {
	if p != pan {
		return acs.Card{}, false, nil
	}
	return acs.Card{Expiry: time.Now().AddDate(2, 0, 0).Format("0601"), Status: "ACTIVE", Channels: []string{"sms"}}, true, nil
}

type frm struct{ v acs.Verdict }

func (f frm) Evaluate(context.Context, string, string, string, int64, string) (acs.Verdict, string) {
	return f.v, "test"
}

type otpBox struct {
	mu   sync.Mutex
	last string
}

func (o *otpBox) Send(_ context.Context, _ string, _ acs.Card, _, otp string) error {
	o.mu.Lock()
	o.last = otp
	o.mu.Unlock()
	return nil
}

type noOOB struct{}

func (noOOB) Notify(context.Context, string, string, string, int64, string) error { return nil }

// threeDSServer receives RReqs (its threeDSServerURL) and answers RRes.
type threeDSServer struct {
	mu  sync.Mutex
	got []map[string]any
}

func (s *threeDSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rr map[string]any
	_ = json.NewDecoder(r.Body).Decode(&rr)
	s.mu.Lock()
	s.got = append(s.got, rr)
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"messageType": "RRes", "messageVersion": "2.3.1", "resultsStatus": "01",
		"threeDSServerTransID": rr["threeDSServerTransID"].(string), "dsTransID": rr["dsTransID"].(string), "acsTransID": rr["acsTransID"].(string)})
}

// net: a real ACS (issuer, BIN 437551) and the DS on HTTP, a 3DS Server results endpoint, one security module
// stand-in shared by ACS, DS and the verifier.
type net struct {
	ds, acsURL, srvURL string
	acs                *acs.ACS
	hsm                *threedstest.HSM
	otp                *otpBox
	srv                *threeDSServer
}

func newNet(t *testing.T, verdict acs.Verdict, extra ...ds.Range) *net {
	n := &net{hsm: threedstest.New(), otp: &otpBox{}, srv: &threeDSServer{}}
	var dsHandler http.Handler
	dsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dsHandler.ServeHTTP(w, r) }))
	t.Cleanup(dsSrv.Close)
	n.acs = acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "http://acs/3ds/challenge", PayerKey: []byte("test-key-0123456789")},
		cards{}, frm{verdict}, n.hsm, n.otp, noOOB{}, acs.NewDSClient(dsSrv.URL+"/3ds/rreq"))
	acsSrv := httptest.NewServer(n.acs.Handler())
	t.Cleanup(acsSrv.Close)
	srv := httptest.NewServer(n.srv)
	t.Cleanup(srv.Close)
	n.ds, n.acsURL, n.srvURL = dsSrv.URL, acsSrv.URL, srv.URL
	ranges := append([]ds.Range{{Prefix: "437551", ACSURL: acsSrv.URL + "/3ds/areq"}}, extra...)
	dsHandler = ds.New(ds.Config{Ranges: ranges, HSM: n.hsm, URL: dsSrv.URL + "/3ds/rreq"}).Handler()
	return n
}

func (n *net) areq(card string, amount string) map[string]any {
	return map[string]any{"messageType": "AReq", "messageVersion": "2.3.1", "messageCategory": "01", "deviceChannel": "02",
		"threeDSServerTransID": "srv-1", "threeDSServerURL": n.srvURL + "/results", "acctNumber": card, "purchaseAmount": amount,
		"purchaseCurrency": "356", "merchantName": "Shop", "acquirerMerchantID": "MERCHANT01", "notificationURL": "https://merchant.example/3ds"}
}

func post(t *testing.T, url string, body any) (map[string]any, int) {
	t.Helper()
	b, _ := json.Marshal(body)
	r, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out, r.StatusCode
}

func s(m map[string]any, k string) string { v, _ := m[k].(string); return v }

func TestRoutingAndParseRanges(t *testing.T) {
	d := ds.New(ds.Config{Ranges: []ds.Range{{Prefix: "4375", ACSURL: "http://a"}, {Prefix: "437551", ACSURL: "http://b"}, {Prefix: "5", ACSURL: "http://c"}}})
	for in, want := range map[string]string{"4375510000000001": "http://b", "4375990000000001": "http://a", "5100000000000000": "http://c", "6011000000000000": ""} {
		if got := d.Route(in); got != want {
			t.Errorf("%s → %q, want %q", in, got, want)
		}
	}
	if rs, err := ds.ParseRanges([]byte(`[{"prefix":"437551","acsURL":"http://acs:8090/3ds/areq"}]`)); err != nil || len(rs) != 1 || rs[0].ACSURL != "http://acs:8090/3ds/areq" {
		t.Fatalf("%v %+v", err, rs)
	}
	for _, bad := range []string{`{}`, `[{"prefix":"43x","acsURL":"http://a"}]`, `[{"prefix":"","acsURL":"http://a"}]`, `[{"prefix":"4","acsURL":"ftp://a"}]`} {
		if _, err := ds.ParseRanges([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// AReq through the DS to the issuer's ACS (challenge), CReq to the ACS, RReq from the ACS through the DS to the
// 3DS Server's threeDSServerURL.
func TestChallengeThroughTheDSWithRReqRelay(t *testing.T) {
	n := newNet(t, acs.Alert)
	ares, code := post(t, n.ds+"/3ds/areq", n.areq(pan, "1000"))
	dsID := s(ares, "dsTransID")
	if code != 200 || s(ares, "transStatus") != "C" || dsID == "" || s(ares, "dsReferenceNumber") != "DIFME-DS-SIM" || s(ares, "acsTransID") == "" {
		t.Fatalf("%d %v", code, ares)
	}
	creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: s(ares, "acsTransID"), ChallengeDataEntry: n.otp.last}
	cres, err := n.acs.Challenge(context.Background(), creq)
	if err != nil || cres.TransStatus != "Y" {
		t.Fatalf("%v %+v", err, cres)
	}
	if len(n.srv.got) != 1 {
		t.Fatalf("RReqs at the 3DS Server: %v", n.srv.got)
	}
	rr := n.srv.got[0]
	if s(rr, "messageType") != "RReq" || s(rr, "dsTransID") != dsID || s(rr, "transStatus") != "Y" || s(rr, "eci") != "05" {
		t.Fatalf("relayed RReq: %v", rr)
	}
	if _, err := threeds.Verify(context.Background(), n.hsm, pan, s(rr, "authenticationValue")); err != nil {
		t.Fatalf("CAVV in the relayed RReq: %v", err)
	}
	// relayed once: a repeated RReq for the transaction is refused
	if _, code := post(t, n.ds+"/3ds/rreq", rr); code != 400 {
		t.Errorf("second RReq: %d", code)
	}
	if out, code := post(t, n.ds+"/3ds/rreq", map[string]any{"messageType": "RReq", "dsTransID": "nope"}); code != 400 {
		t.Errorf("unknown dsTransID: %d %v", code, out)
	}
}

func TestFrictionlessThroughTheDS(t *testing.T) {
	n := newNet(t, acs.NoAlert)
	ares, code := post(t, n.ds+"/3ds/areq", n.areq(pan, "1000"))
	if code != 200 || s(ares, "transStatus") != "Y" || s(ares, "eci") != "05" || s(ares, "dsTransID") == "" {
		t.Fatalf("%d %v", code, ares)
	}
	// the issuer's own answers pass through: unknown card at an enrolled range → N/08 from the ACS
	ares, _ = post(t, n.ds+"/3ds/areq", n.areq("4375519999999999", "1000"))
	if s(ares, "transStatus") != "N" || s(ares, "transStatusReason") != "08" {
		t.Fatalf("ACS answer not relayed: %v", ares)
	}
}

func checkAttempts(t *testing.T, n *net, ares map[string]any, card string) {
	t.Helper()
	if s(ares, "transStatus") != "A" || s(ares, "eci") != "06" || s(ares, "dsTransID") == "" || s(ares, "acsTransID") == "" {
		t.Fatalf("stand-in: %v", ares)
	}
	c, err := threeds.Verify(context.Background(), n.hsm, card, s(ares, "authenticationValue"))
	if err != nil || c.Result != threeds.ResultAttempt || c.ECI != 6 || c.SecondFactor != 0 {
		t.Fatalf("attempts CAVV: %v %+v", err, c)
	}
}

func TestStandInAttempts(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", 503) }))
	t.Cleanup(failing.Close)
	n := newNet(t, acs.Alert, ds.Range{Prefix: "411111", ACSURL: closedURL + "/3ds/areq"}, ds.Range{Prefix: "422222", ACSURL: failing.URL + "/3ds/areq"})

	t.Run("unknown range", func(t *testing.T) {
		ares, code := post(t, n.ds+"/3ds/areq", n.areq("6011000000000004", "1000"))
		if code != 200 {
			t.Fatal(code)
		}
		checkAttempts(t, n, ares, "6011000000000004")
		// The CAVV's cryptographic part is a 3-digit CVV, so another card matches by chance 1 time in 1000. Check
		// three other cards and fail only if all match (about 1 in 10^9).
		rejected := 0
		for _, other := range []string{pan, "4375510000000019", "4375510000000027"} {
			_, err := threeds.Verify(context.Background(), n.hsm, other, s(ares, "authenticationValue"))
			if errors.Is(err, threeds.ErrCryptogram) {
				rejected++
			} else if err != nil {
				t.Fatalf("verify for %s: %v", other, err)
			}
		}
		if rejected == 0 {
			t.Errorf("attempts CAVV verified for three other cards")
		}
	})
	t.Run("ACS unreachable", func(t *testing.T) {
		ares, _ := post(t, n.ds+"/3ds/areq", n.areq("4111110000000003", "1000"))
		checkAttempts(t, n, ares, "4111110000000003")
	})
	t.Run("ACS 5xx", func(t *testing.T) {
		ares, _ := post(t, n.ds+"/3ds/areq", n.areq("4222220000000001", "1000"))
		checkAttempts(t, n, ares, "4222220000000001")
	})
	t.Run("security module down", func(t *testing.T) {
		d := ds.New(ds.Config{HSM: brokenHSM{}})
		res, _, err := d.AReq(context.Background(), n.areq("6011000000000004", "1000"))
		if err != nil || res["transStatus"] != "U" || res["authenticationValue"] != nil {
			t.Fatalf("%v %v", err, res)
		}
	})
}

type brokenHSM struct{}

func (brokenHSM) CAVV(context.Context, string, string, string, string) (string, error) {
	return "", errors.New("down")
}
func (brokenHSM) VerifyCAVV(context.Context, string, string, string, string, string) (bool, error) {
	return false, errors.New("down")
}

func TestBadAReqs(t *testing.T) {
	n := newNet(t, acs.Alert)
	for name, mut := range map[string]func(m map[string]any){
		"no threeDSServerURL": func(m map[string]any) { delete(m, "threeDSServerURL") },
		"bad version":         func(m map[string]any) { m["messageVersion"] = "2.1.0" },
		"bad PAN":             func(m map[string]any) { m["acctNumber"] = "4375x" },
		"not an AReq":         func(m map[string]any) { m["messageType"] = "CReq" },
	} {
		q := n.areq(pan, "1000")
		mut(q)
		if out, code := post(t, n.ds+"/3ds/areq", q); code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// the ACS refusing the message (no purchaseAmount on a payment): its 400 goes back, no stand-in
	q := n.areq(pan, "")
	if out, code := post(t, n.ds+"/3ds/areq", q); code != 400 || out["transStatus"] != nil {
		t.Errorf("ACS refusal: %d %v", code, out)
	}
}

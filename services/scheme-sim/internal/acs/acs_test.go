package acs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moov-io/iso8583"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/scheme"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/server"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/threeds/threedstest"
	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/wire"
)

const (
	pan    = "4375510000000001"
	appPAN = "4375510000000027" // DIFME app enrolled
	twoPAN = "4375510000000035" // SMS and email
)

type fakeFRM struct {
	verdict acs.Verdict
	calls   []string
}

func (f *fakeFRM) Evaluate(_ context.Context, id, payer, merchant string, amount int64, ccy string) (acs.Verdict, string) {
	f.calls = append(f.calls, fmt.Sprintf("%s %s %d %s", payer, merchant, amount, ccy))
	return f.verdict, "test"
}

type otpBox struct {
	mu            sync.Mutex
	last, channel string
}

func (o *otpBox) Send(_ context.Context, _ string, _ acs.Card, channel, otp string) error {
	o.mu.Lock()
	o.last, o.channel = otp, channel
	o.mu.Unlock()
	return nil
}

type oobBox struct{ pushed []string }

func (o *oobBox) Notify(_ context.Context, _, acsTransID, _ string, _ int64, _ string) error {
	o.pushed = append(o.pushed, acsTransID)
	return nil
}

type rreqBox struct{ got []acs.RReq }

func (r *rreqBox) Send(_ context.Context, rr acs.RReq) error { r.got = append(r.got, rr); return nil }

// world: the scheme simulator (CMS + authorisation switch) on real HTTP, the ACS reading cards from it, one security
// module stand-in shared by ACS and switch (as both call services/hsm).
type world struct {
	net   *scheme.Network
	acs   *acs.ACS
	frm   *fakeFRM
	otp   *otpBox
	oob   *oobBox
	rreqs *rreqBox
	now   time.Time
}

func newWorld(t *testing.T, verdict acs.Verdict) *world {
	n := scheme.New()
	hsm := threedstest.New()
	n.HSM = hsm
	exp := time.Now().AddDate(2, 0, 0).Format("0601")
	for _, c := range []scheme.Card{{PAN: pan, Expiry: exp, LimitMinor: 10_000_000, Status: "ACTIVE"},
		{PAN: "4375510000000019", Expiry: exp, LimitMinor: 10_000_000, Status: "BLOCKED"},
		{PAN: appPAN, Expiry: exp, LimitMinor: 10_000_000, Status: "ACTIVE", Channels: []string{"app", "sms"}},
		{PAN: twoPAN, Expiry: exp, LimitMinor: 10_000_000, Status: "ACTIVE", Channels: []string{"sms", "email"}}} {
		if err := n.PutCard(c); err != nil {
			t.Fatal(err)
		}
	}
	cms := httptest.NewServer(server.Admin(n))
	t.Cleanup(cms.Close)
	w := &world{net: n, frm: &fakeFRM{verdict: verdict}, otp: &otpBox{}, oob: &oobBox{}, rreqs: &rreqBox{}, now: time.Now()}
	w.acs = acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "http://acs/3ds/creq", PayerKey: []byte("test-key-0123456789"),
		Now: func() time.Time { return w.now }}, acs.NewCMSClient(cms.URL), w.frm, hsm, w.otp, w.oob, w.rreqs)
	return w
}

func areq(card string, amount int64) acs.AReq {
	return acs.AReq{MessageType: "AReq", MessageVersion: "2.3.1", MessageCategory: "01", DeviceChannel: "02", ThreeDSServerTransID: "srv-1",
		DSTransID: "ds-1", AcctNumber: card, PurchaseAmount: fmt.Sprint(amount), PurchaseCurrency: "356", MerchantName: "Shop", AcquirerMerchantID: "MERCHANT01"}
}

var stan = 100

// authorise sends a 0100 to the switch with the CAVV in field 48.
func authorise(t *testing.T, n *scheme.Network, amount int64, cavv string) string {
	t.Helper()
	stan++
	m := iso8583.NewMessage(wire.Spec)
	m.MTI("0100")
	for id, v := range map[int]string{2: pan, 3: "000000", 4: fmt.Sprintf("%012d", amount), 11: fmt.Sprintf("%06d", stan), 41: "TERM0001", 42: "MERCHANT01", 49: "356"} {
		_ = m.Field(id, v)
	}
	if cavv != "" {
		_ = m.Field(48, "CAVV:"+cavv)
	}
	r, err := n.Handle(m)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Get(r, 39)
}

func TestFrictionlessThenAuthorisedOnceWithTheCAVV(t *testing.T) {
	w := newWorld(t, acs.NoAlert)
	res, err := w.acs.Authenticate(context.Background(), areq(pan, 150_000))
	if err != nil || res.TransStatus != "Y" || res.ECI != "05" || res.AuthenticationValue == "" {
		t.Fatalf("%v %+v", err, res)
	}
	if len(w.frm.calls) != 1 || strings.Contains(w.frm.calls[0], pan) || !strings.HasPrefix(w.frm.calls[0], "card-") {
		t.Fatalf("FRM must get an opaque card reference, not the PAN: %v", w.frm.calls)
	}
	if code := authorise(t, w.net, 150_000, res.AuthenticationValue); code != scheme.Approved {
		t.Fatalf("authorisation with CAVV: %s", code)
	}
	if tx := w.net.Transactions(1)[0]; tx.ECI != "05" {
		t.Fatalf("ECI on the transaction: %q", tx.ECI)
	}
	if code := authorise(t, w.net, 150_000, res.AuthenticationValue); code != scheme.DoNotHonour {
		t.Errorf("replayed CAVV: %s", code)
	}
	d, _ := threeds.Decode(res.AuthenticationValue)
	d.CVV = fmt.Sprintf("%03d", (atoi(d.CVV)+1)%1000)
	if code := authorise(t, w.net, 1000, d.Encode()); code != scheme.DoNotHonour {
		t.Errorf("forged CAVV: %s", code)
	}
	if code := authorise(t, w.net, 1000, "not-a-cavv"); code != scheme.DoNotHonour {
		t.Errorf("malformed CAVV: %s", code)
	}
}

func atoi(s string) (n int) { fmt.Sscan(s, &n); return }

func TestChallengeWithPasscode(t *testing.T) {
	w := newWorld(t, acs.Alert) // FRM alert: step up
	res, _ := w.acs.Authenticate(context.Background(), areq(pan, 1000))
	if res.TransStatus != "C" || res.ACSURL == "" || w.otp.last == "" || res.AuthenticationValue != "" {
		t.Fatalf("%+v otp=%q", res, w.otp.last)
	}
	creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.2.0", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID}
	creq.ChallengeDataEntry = "000000"
	if w.otp.last == "000000" {
		creq.ChallengeDataEntry = "111111"
	}
	cres, err := w.acs.Challenge(context.Background(), creq)
	if err != nil || cres.ChallengeCompletionInd != "N" || !strings.Contains(cres.ChallengeInfoText, "2 attempt") {
		t.Fatalf("wrong code: %v %+v", err, cres)
	}
	creq.ChallengeDataEntry = w.otp.last
	cres, _ = w.acs.Challenge(context.Background(), creq)
	if cres.TransStatus != "Y" || len(w.rreqs.got) != 1 {
		t.Fatalf("%+v rreqs=%v", cres, w.rreqs.got)
	}
	rr := w.rreqs.got[0]
	if rr.TransStatus != "Y" || rr.ECI != "05" || rr.InteractionCounter != "02" || rr.DSTransID != "ds-1" {
		t.Fatalf("RReq: %+v", rr)
	}
	if c, _ := threeds.Decode(rr.AuthenticationValue); c.Result != threeds.ResultChallenge || c.SecondFactor != 1 {
		t.Fatalf("CAVV result codes: %+v", c)
	}
	if code := authorise(t, w.net, 1000, rr.AuthenticationValue); code != scheme.Approved {
		t.Fatalf("authorisation after challenge: %s", code)
	}
	if _, err := w.acs.Challenge(context.Background(), creq); err == nil {
		t.Error("a completed challenge accepted another CReq")
	}
}

func TestChallengeFailures(t *testing.T) {
	w := newWorld(t, acs.NoAlert)
	// above the frictionless limit: challenged although FRM is clear
	res, _ := w.acs.Authenticate(context.Background(), areq(pan, 900_000))
	if res.TransStatus != "C" {
		t.Fatalf("over limit: %+v", res)
	}
	creq := acs.CReq{MessageType: "CReq", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID, ChallengeDataEntry: "x"}
	for i := 0; i < 3; i++ {
		_, _ = w.acs.Challenge(context.Background(), creq)
	}
	if last := w.rreqs.got[len(w.rreqs.got)-1]; last.TransStatus != "N" || last.TransStatusReason != acs.ReasonMaxChallenge || last.AuthenticationValue != "" {
		t.Fatalf("after 3 wrong codes: %+v", last)
	}
	// expired passcode
	res, _ = w.acs.Authenticate(context.Background(), areq(pan, 900_000))
	w.now = w.now.Add(6 * time.Minute)
	creq.ACSTransID, creq.ChallengeDataEntry = res.ACSTransID, w.otp.last
	if cres, _ := w.acs.Challenge(context.Background(), creq); cres.TransStatus != "N" {
		t.Fatalf("expired: %+v", cres)
	}
	if last := w.rreqs.got[len(w.rreqs.got)-1]; last.TransStatusReason != acs.ReasonTimedOut {
		t.Fatalf("expired reason: %+v", last)
	}
	// requestor mandates a challenge
	w.now = time.Now()
	q := areq(pan, 1000)
	q.ChallengeIndicator = "04"
	if res, _ := w.acs.Authenticate(context.Background(), q); res.TransStatus != "C" {
		t.Fatalf("mandated: %+v", res)
	}
}

func TestDeclinedAuthentications(t *testing.T) {
	w := newWorld(t, acs.Interdict)
	for _, c := range []struct{ card, status, reason string }{
		{pan, "R", acs.ReasonFraud},                       // FRM interdiction
		{"4375510000000019", "N", acs.ReasonNotPermitted}, // blocked in CMS
		{"4375510000000043", "N", acs.ReasonNoCardRecord}, // unknown card
	} {
		res, err := w.acs.Authenticate(context.Background(), areq(c.card, 1000))
		if err != nil || res.TransStatus != c.status || res.TransStatusReason != c.reason || res.AuthenticationValue != "" {
			t.Errorf("%s: %v %+v", c.card, err, res)
		}
	}
	if _, err := w.acs.Authenticate(context.Background(), acs.AReq{MessageType: "AReq"}); err == nil {
		t.Error("an incomplete AReq was accepted")
	}
}

func TestHTTPAndTazamaClient(t *testing.T) {
	// Tazama: TMS accepts, admin answers 204 once then an ALRT report
	polls := 0
	tz := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/evaluate/iso20022/"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.Contains(fmt.Sprint(body), pan) {
				rw.WriteHeader(400)
				return
			}
			_, _ = rw.Write([]byte(`{"message":"Transaction is valid"}`))
		case r.URL.Path == "/v1/admin/reports/getreportbymsgid":
			if polls++; polls == 1 {
				rw.WriteHeader(204)
				return
			}
			_, _ = rw.Write([]byte(`{"data":{"report":{"status":"ALRT","tadpResult":{"typologyResult":[{"cfg":"difme-fraud-model@1.0.0","result":200,"workflow":{"alertThreshold":200,"interdictionThreshold":400}}]}}}}`))
		}
	}))
	defer tz.Close()
	v, detail := acs.NewTazama(tz.URL, tz.URL, 2*time.Second).Evaluate(context.Background(), "3ds-x", "card-abc", "MERCHANT01", 1000, "INR")
	if v != acs.Alert || !strings.Contains(detail, "difme-fraud-model@1.0.0=200") {
		t.Fatalf("%s %s", v, detail)
	}
	if v, _ := acs.ParseEvaluation([]byte(`{"report":{"status":"ALRT","tadpResult":{"typologyResult":[{"cfg":"t","result":400,"workflow":{"interdictionThreshold":400}}]}}}`)); v != acs.Interdict {
		t.Errorf("interdiction: %s", v)
	}

	// the ACS over HTTP
	w := newWorld(t, acs.NoAlert)
	srv := httptest.NewServer(w.acs.Handler())
	defer srv.Close()
	b, _ := json.Marshal(areq(pan, 1000))
	r, err := http.Post(srv.URL+"/3ds/areq", "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	var res acs.ARes
	_ = json.NewDecoder(r.Body).Decode(&res)
	if r.StatusCode != 200 || res.TransStatus != "Y" || res.MessageType != "ARes" {
		t.Fatalf("%d %+v", r.StatusCode, res)
	}
	if r, _ := http.Post(srv.URL+"/3ds/creq", "application/json", strings.NewReader(`{"messageType":"CReq","acsTransID":"nope"}`)); r.StatusCode != 400 {
		t.Errorf("unknown challenge: %d", r.StatusCode)
	}
}

func TestVersions(t *testing.T) {
	w := newWorld(t, acs.NoAlert)
	for _, v := range []string{"2.3.1", "2.2.0"} {
		q := areq(pan, 1000)
		q.MessageVersion = v
		if res, err := w.acs.Authenticate(context.Background(), q); err != nil || res.MessageVersion != v || res.TransStatus != "Y" {
			t.Errorf("%s: %v %+v", v, err, res)
		}
	}
	q := areq(pan, 1000)
	q.MessageVersion = "2.1.0"
	if _, err := w.acs.Authenticate(context.Background(), q); err == nil {
		t.Error("2.1.0 accepted")
	}
}

func TestSingleSelectThenPasscode(t *testing.T) {
	w := newWorld(t, acs.Alert)
	res, _ := w.acs.Authenticate(context.Background(), areq(twoPAN, 1000))
	if res.TransStatus != "C" || res.ACSRenderingType == nil || res.ACSRenderingType.Template != "06" && res.ACSRenderingType.Template != "02" || w.otp.last != "" {
		t.Fatalf("%+v %+v", res, res.ACSRenderingType)
	}
	creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID}
	cres, _ := w.acs.Challenge(context.Background(), creq)
	if cres.ACSUIType != "02" || len(cres.ChallengeSelectInfo) != 2 {
		t.Fatalf("select screen: %+v", cres)
	}
	creq.ChallengeDataEntry = "email"
	cres, _ = w.acs.Challenge(context.Background(), creq)
	if cres.ACSUIType != "01" || w.otp.channel != "email" || w.otp.last == "" {
		t.Fatalf("after choosing email: %+v channel=%q", cres, w.otp.channel)
	}
	creq.ChallengeDataEntry = w.otp.last
	if cres, _ = w.acs.Challenge(context.Background(), creq); cres.TransStatus != "Y" {
		t.Fatalf("%+v", cres)
	}
	if rr := w.rreqs.got[0]; rr.AuthenticationType != acs.AuthOTP || rr.MessageVersion != "2.3.1" {
		t.Fatalf("%+v", rr)
	}
}

func TestOutOfBandAppApproval(t *testing.T) {
	w := newWorld(t, acs.Alert)
	res, _ := w.acs.Authenticate(context.Background(), areq(appPAN, 1000))
	if res.TransStatus != "C" || res.AuthenticationType != acs.AuthOOB || len(w.oob.pushed) != 1 {
		t.Fatalf("%+v pushes=%v", res, w.oob.pushed)
	}
	creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID, OOBContinue: "Y"}
	if cres, _ := w.acs.Challenge(context.Background(), creq); cres.ACSUIType != "04" || cres.ChallengeCompletionInd != "N" {
		t.Fatalf("before approval: %+v", cres)
	}
	if err := w.acs.OOBResult(context.Background(), res.ACSTransID, true); err != nil {
		t.Fatal(err)
	}
	if cres, _ := w.acs.Challenge(context.Background(), creq); cres.TransStatus != "Y" {
		t.Fatalf("after approval: %+v", cres)
	}
	rr := w.rreqs.got[0]
	if c, _ := threeds.Decode(rr.AuthenticationValue); rr.AuthenticationType != acs.AuthOOB || c.SecondFactor != 2 {
		t.Fatalf("%+v %+v", rr, c)
	}
	if code := authorise(t, w.net, 1000, rr.AuthenticationValue); code != scheme.DoNotHonour {
		// the CAVV belongs to appPAN, authorise() pays with pan: must not verify
		t.Fatalf("CAVV of another card accepted: %s", code)
	}
}

func TestDecoupledAuthentication(t *testing.T) {
	w := newWorld(t, acs.Alert)
	q := areq(appPAN, 1000)
	q.DecReqInd, q.DecMaxTime = "Y", "5"
	res, _ := w.acs.Authenticate(context.Background(), q)
	if res.TransStatus != "D" || res.ACSDecConInd != "Y" || res.AuthenticationType != acs.AuthDecoupled {
		t.Fatalf("%+v", res)
	}
	if _, err := w.acs.Challenge(context.Background(), acs.CReq{MessageType: "CReq", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID}); err == nil {
		t.Error("a decoupled authentication accepted a CReq")
	}
	_ = w.acs.OOBResult(context.Background(), res.ACSTransID, true)
	if rr := w.rreqs.got[0]; rr.TransStatus != "Y" || rr.AuthenticationType != acs.AuthDecoupled || rr.AuthenticationValue == "" {
		t.Fatalf("%+v", rr)
	}
	// a second one is never approved: expires after DecMaxTime
	res, _ = w.acs.Authenticate(context.Background(), q)
	w.now = w.now.Add(6 * time.Minute)
	w.acs.Expire(context.Background())
	if rr := w.rreqs.got[1]; rr.TransStatus != "N" || rr.TransStatusReason != acs.ReasonDecoupledExp {
		t.Fatalf("expired: %+v", rr)
	}
}

func TestThreeRI(t *testing.T) {
	w := newWorld(t, acs.NoAlert)
	q := areq(pan, 0)
	q.DeviceChannel, q.MessageCategory, q.PurchaseAmount = "03", "02", ""
	if res, _ := w.acs.Authenticate(context.Background(), q); res.TransStatus != "Y" || res.AuthenticationValue == "" {
		t.Fatalf("3RI NPA: %+v", res)
	}
	q = areq(pan, 1000)
	q.DeviceChannel = "03"
	if res, _ := w.acs.Authenticate(context.Background(), q); res.TransStatus != "N" || res.TransStatusReason != acs.Reason3RINotSupp {
		t.Fatalf("3RI PA: %+v", res)
	}
}

func TestBrowserChallengePage(t *testing.T) {
	w := newWorld(t, acs.Alert)
	srv := httptest.NewServer(w.acs.Handler())
	defer srv.Close()
	q := areq(pan, 1000)
	q.NotificationURL = "https://merchant.example/3ds/notify"
	res, _ := w.acs.Authenticate(context.Background(), q)
	creq, _ := json.Marshal(acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID})
	post := func(form url.Values) string {
		r, err := http.PostForm(srv.URL+"/3ds/challenge", form)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("%d %s", r.StatusCode, b)
		}
		return string(b)
	}
	html := post(url.Values{"creq": {base64.RawURLEncoding.EncodeToString(creq)}, "threeDSSessionData": {"sess-1"}})
	if !strings.Contains(html, `name="challengeDataEntry"`) || !strings.Contains(html, res.ACSTransID) {
		t.Fatalf("challenge page: %s", html)
	}
	html = post(url.Values{"acsTransID": {res.ACSTransID}, "threeDSServerTransID": {"srv-1"}, "messageVersion": {"2.3.1"},
		"threeDSSessionData": {"sess-1"}, "challengeDataEntry": {w.otp.last}})
	if !strings.Contains(html, `action="https://merchant.example/3ds/notify"`) || !strings.Contains(html, `value="sess-1"`) {
		t.Fatalf("final page: %s", html)
	}
	enc := html[strings.Index(html, `name="cres" value="`)+len(`name="cres" value="`):]
	enc = enc[:strings.Index(enc, `"`)]
	b, _ := base64.RawURLEncoding.DecodeString(enc)
	var cres acs.CRes
	if err := json.Unmarshal(b, &cres); err != nil || cres.TransStatus != "Y" || cres.ChallengeCompletionInd != "Y" {
		t.Fatalf("cres: %v %s", err, b)
	}
}

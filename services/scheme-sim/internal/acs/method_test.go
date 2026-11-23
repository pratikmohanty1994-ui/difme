package acs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
)

const ua = "Mozilla/5.0 (X11; Linux x86_64) DIFME-test"

// runMethod plays the 3DS Server's hidden iframe: loads the method page, then posts the data its script would collect.
func runMethod(t *testing.T, srv string, id string, dev map[string]string) {
	t.Helper()
	md, _ := json.Marshal(map[string]string{"threeDSServerTransID": id, "threeDSMethodNotificationURL": "https://requestor.example/method-done"})
	r, err := http.PostForm(srv+"/3ds/method", url.Values{"threeDSMethodData": {base64.RawURLEncoding.EncodeToString(md)}})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	back, _ := json.Marshal(map[string]string{"threeDSServerTransID": id})
	if r.StatusCode != 200 || !strings.Contains(string(page), "https://requestor.example/method-done") ||
		!strings.Contains(string(page), base64.RawURLEncoding.EncodeToString(back)) || !strings.Contains(string(page), "method/collect") {
		t.Fatalf("method page: %d %s", r.StatusCode, page)
	}
	body, _ := json.Marshal(dev)
	c, err := http.Post(srv+"/3ds/method/collect?id="+url.QueryEscape(id), "application/json", strings.NewReader(string(body)))
	if err != nil || c.StatusCode != http.StatusNoContent {
		t.Fatalf("collect: %v %v", err, c)
	}
}

func browserAReq(id, userAgent string) acs.AReq {
	q := areq(pan, 1000)
	q.ThreeDSServerTransID, q.ThreeDSCompInd, q.BrowserUserAgent, q.BrowserLanguage, q.BrowserTZ = id, "Y", userAgent, "en-IN", "-330"
	return q
}

func TestThreeDSMethodDeviceRisk(t *testing.T) {
	w := newWorld(t, acs.NoAlert) // FRM clear, amount under the frictionless limit: only device data decides
	hs := httptest.NewServer(w.acs.Handler())
	t.Cleanup(hs.Close)
	srv := hs.URL
	dev := map[string]string{"ua": ua, "lang": "en-IN", "tz": "-330", "screen": "1920x1080", "depth": "24", "platform": "Linux x86_64", "cores": "8"}
	ctx := context.Background()

	// first purchase from this device: method ran, device unknown for the card -> challenge
	runMethod(t, srv, "srv-a", dev)
	res, err := w.acs.Authenticate(ctx, browserAReq("srv-a", ua))
	if err != nil || res.TransStatus != "C" {
		t.Fatalf("unknown device: %v %+v", err, res)
	}
	creq := acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-a", ACSTransID: res.ACSTransID, ChallengeDataEntry: w.otp.last}
	if cres, err := w.acs.Challenge(ctx, creq); err != nil || cres.TransStatus != "Y" {
		t.Fatalf("challenge: %v %+v", err, cres)
	}
	// the device passed a challenge for this card: next purchase from it is frictionless
	runMethod(t, srv, "srv-b", dev)
	if res, err := w.acs.Authenticate(ctx, browserAReq("srv-b", ua)); err != nil || res.TransStatus != "Y" {
		t.Fatalf("known device: %v %+v", err, res)
	}
	// AReq browser data that does not match what the method page saw -> challenge
	runMethod(t, srv, "srv-c", dev)
	if res, _ := w.acs.Authenticate(ctx, browserAReq("srv-c", "curl/8.0")); res.TransStatus != "C" {
		t.Fatalf("user agent mismatch: %+v", res)
	}
	// threeDSCompInd Y but nothing collected for that transaction -> challenge
	if res, _ := w.acs.Authenticate(ctx, browserAReq("srv-never", ua)); res.TransStatus != "C" {
		t.Fatalf("no method data: %+v", res)
	}
	// another device on the same card -> challenge
	other := map[string]string{"ua": ua, "lang": "en-IN", "tz": "-330", "screen": "390x844", "depth": "24", "platform": "iPhone", "cores": "6"}
	runMethod(t, srv, "srv-d", other)
	if res, _ := w.acs.Authenticate(ctx, browserAReq("srv-d", ua)); res.TransStatus != "C" {
		t.Fatalf("new device: %+v", res)
	}
	// method not run (threeDSCompInd N): unchanged behaviour, frictionless on a clear verdict
	q := areq(pan, 1000)
	q.ThreeDSCompInd = "N"
	if res, _ := w.acs.Authenticate(ctx, q); res.TransStatus != "Y" {
		t.Fatalf("no 3DS Method: %+v", res)
	}
	// malformed threeDSMethodData is refused
	if r, _ := http.PostForm(srv+"/3ds/method", url.Values{"threeDSMethodData": {"not-base64!"}}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad method data: %d", r.StatusCode)
	}
}

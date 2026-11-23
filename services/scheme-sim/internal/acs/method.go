package acs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 3DS Method (EMV 3DS 2.3.1, browser channel): before the AReq, the 3DS Server loads the ACS's 3DS Method URL in a
// hidden iframe, posting form field threeDSMethodData (base64url JSON {threeDSServerTransID,
// threeDSMethodNotificationURL}). The ACS's page collects browser/device data, then posts threeDSMethodData
// (base64url JSON {threeDSServerTransID}) to the notification URL; the AReq then carries threeDSCompInd Y.
//
// Risk use (deviceRisk): when the method ran, the AReq's browser data must match what the page collected, and the
// device must have authenticated this card before (a challenge it passed). Otherwise the ACS challenges instead of
// answering frictionless. Without method data (threeDSCompInd N/U, app channel) nothing changes. Device data is kept
// in process memory: collected data for MethodTTL, known devices per card reference (HMAC, no card number) for
// KnownDeviceTTL.

const (
	MethodTTL      = 10 * time.Minute
	KnownDeviceTTL = 180 * 24 * time.Hour
)

// Device is what the 3DS Method page collected.
type Device struct {
	UserAgent  string `json:"ua"`
	Language   string `json:"lang"`
	TZ         string `json:"tz"` // minutes from UTC, as browserTZ
	Screen     string `json:"screen"`
	ColorDepth string `json:"depth"`
	Platform   string `json:"platform"`
	Cores      string `json:"cores"`
	IP         string `json:"-"` // from the collect request
	At         time.Time
}

// Hash identifies the device (attributes that don't change between purchases; not the IP).
func (d Device) Hash() string {
	h := sha256.Sum256([]byte(strings.Join([]string{d.UserAgent, d.Language, d.TZ, d.Screen, d.ColorDepth, d.Platform, d.Cores}, "\x00")))
	return hex.EncodeToString(h[:16])
}

type deviceRisk struct {
	mu        sync.Mutex
	collected map[string]Device               // threeDSServerTransID -> device
	known     map[string]map[string]time.Time // card reference -> device hash -> last authenticated
}

func newDeviceRisk() *deviceRisk {
	return &deviceRisk{collected: map[string]Device{}, known: map[string]map[string]time.Time{}}
}

func (r *deviceRisk) collect(id string, d Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.collected { // small map: prune on write
		if d.At.Sub(v.At) > MethodTTL {
			delete(r.collected, k)
		}
	}
	r.collected[id] = d
}

func (r *deviceRisk) device(id string, now time.Time) (Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.collected[id]
	return d, ok && now.Sub(d.At) <= MethodTTL
}

func (r *deviceRisk) remember(cardRef, hash string, now time.Time) {
	if cardRef == "" || hash == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.known[cardRef] == nil {
		r.known[cardRef] = map[string]time.Time{}
	}
	r.known[cardRef][hash] = now
}

func (r *deviceRisk) isKnown(cardRef, hash string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.known[cardRef][hash]
	return ok && now.Sub(t) <= KnownDeviceTTL
}

// assess returns the device hash to remember after a successful authentication ("" when the method did not run) and
// whether the device data allows a frictionless answer.
func (a *ACS) assessDevice(q AReq, cardRef string) (hash string, frictionlessOK bool, why string) {
	if q.DeviceChannel != "02" || q.ThreeDSCompInd != "Y" {
		return "", true, "no 3DS Method data"
	}
	d, ok := a.devices.device(q.ThreeDSServerTransID, a.cfg.Now())
	if !ok {
		return "", false, "threeDSCompInd Y but no collected data"
	}
	if q.BrowserUserAgent != "" && q.BrowserUserAgent != d.UserAgent || q.BrowserLanguage != "" && !strings.EqualFold(q.BrowserLanguage, d.Language) ||
		q.BrowserTZ != "" && q.BrowserTZ != d.TZ {
		return "", false, "AReq browser data does not match the 3DS Method data"
	}
	h := d.Hash()
	if !a.devices.isKnown(cardRef, h, a.cfg.Now()) {
		return h, false, "device not seen with this card"
	}
	return h, true, "known device"
}

var methodPage = template.Must(template.New("m").Parse(`<!doctype html><html><head><meta charset="utf-8"></head><body>
<form id="n" method="post" action="{{.Notify}}"><input type="hidden" name="threeDSMethodData" value="{{.Back}}"></form>
<div id="m" data-id="{{.ID}}"></div>
<script>(function(){var s=screen,d={ua:navigator.userAgent,lang:navigator.language||'',tz:String(new Date().getTimezoneOffset()),
screen:s.width+'x'+s.height,depth:String(s.colorDepth),platform:navigator.platform||'',cores:String(navigator.hardwareConcurrency||'')};
var x=new XMLHttpRequest();x.open('POST','method/collect?id='+encodeURIComponent(document.getElementById('m').dataset.id));
x.setRequestHeader('content-type','application/json');x.onloadend=function(){document.getElementById('n').submit()};x.send(JSON.stringify(d));})();</script>
</body></html>`))

// methodHandler serves POST /3ds/method (the iframe) and POST /3ds/method/collect (the page's data).
func (a *ACS) methodHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string `json:"threeDSServerTransID"`
		Notify string `json:"threeDSMethodNotificationURL"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.FormValue("threeDSMethodData"), "="))
	if err != nil || json.Unmarshal(raw, &in) != nil || in.ID == "" || !strings.HasPrefix(in.Notify, "https://") && !strings.HasPrefix(in.Notify, "http://") {
		http.Error(w, "threeDSMethodData: base64url JSON with threeDSServerTransID and threeDSMethodNotificationURL", http.StatusBadRequest)
		return
	}
	back, _ := json.Marshal(map[string]string{"threeDSServerTransID": in.ID})
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("cache-control", "no-store")
	_ = methodPage.Execute(w, map[string]string{"ID": in.ID, "Notify": in.Notify, "Back": base64.RawURLEncoding.EncodeToString(back)})
}

func (a *ACS) methodCollect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var d Device
	if id == "" || len(id) > 64 || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&d) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	d.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
	d.At = a.cfg.Now()
	a.devices.collect(id, d)
	w.WriteHeader(http.StatusNoContent)
}

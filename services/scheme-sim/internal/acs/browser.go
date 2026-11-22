package acs

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

// Browser challenge (deviceChannel 02, EMV 3DS 2.3.1): the 3DS Requestor's page posts form field "creq" (base64url
// JSON CReq) and "threeDSSessionData" to the acsURL in an iframe; the ACS renders the challenge; the cardholder's
// answers post back here; the final CRes is posted (base64url, form field "cres") to the AReq's notificationURL.

var page = template.Must(template.New("c").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Verify your purchase</title>
<style>body{font:16px system-ui,sans-serif;margin:16px;max-width:420px}button,input{font:inherit;padding:8px;margin:4px 0}
.err{color:#b00020}</style></head><body>
{{if .Final}}<form id="f" method="post" action="{{.NotificationURL}}"><input type="hidden" name="cres" value="{{.CRes}}">
<input type="hidden" name="threeDSSessionData" value="{{.Session}}"><noscript><button>Continue</button></noscript></form>
<script>document.getElementById('f').submit()</script>
{{else}}<h1>{{.Header}}</h1><p>{{.Text}}</p>
<form method="post"><input type="hidden" name="acsTransID" value="{{.ACSTransID}}"><input type="hidden" name="threeDSServerTransID" value="{{.ServerID}}">
<input type="hidden" name="threeDSSessionData" value="{{.Session}}"><input type="hidden" name="messageVersion" value="{{.Version}}">
{{if eq .UI "02"}}{{range .Choices}}{{range $k, $v := .}}<p><button name="challengeDataEntry" value="{{$k}}">{{$v}}</button></p>{{end}}{{end}}
{{else if eq .UI "04"}}<p><button name="oobContinue" value="Y">{{.Continue}}</button></p>
{{else}}<label>Code <input name="challengeDataEntry" inputmode="numeric" autocomplete="one-time-code" maxlength="8" autofocus></label>
<p><button>Submit</button> {{if .Resend}}<button name="resendChallenge" value="Y">{{.Resend}}</button>{{end}}</p>{{end}}
<p><button name="challengeCancel" value="01">Cancel</button></p></form>{{end}}
</body></html>`))

type view struct {
	Final                                                 bool
	NotificationURL                                       template.URL
	CRes, Session, Header, Text, ACSTransID, ServerID, UI string
	Version, Continue, Resend                             string
	Choices                                               []Choice
}

func (a *ACS) browserChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form required", 400)
		return
	}
	var q CReq
	if enc := r.PostForm.Get("creq"); enc != "" {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(enc, "="))
		if err != nil || json.Unmarshal(b, &q) != nil {
			http.Error(w, "creq: base64url JSON CReq required", 400)
			return
		}
	} else {
		q = CReq{MessageType: "CReq", MessageVersion: r.PostForm.Get("messageVersion"), ACSTransID: r.PostForm.Get("acsTransID"),
			ThreeDSServerTransID: r.PostForm.Get("threeDSServerTransID"), ChallengeDataEntry: r.PostForm.Get("challengeDataEntry"),
			OOBContinue: r.PostForm.Get("oobContinue"), ChallengeCancel: r.PostForm.Get("challengeCancel"), ResendChallenge: r.PostForm.Get("resendChallenge")}
	}
	notify := a.notificationURL(q.ACSTransID)
	res, err := a.Challenge(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	v := view{Session: r.PostForm.Get("threeDSSessionData"), ACSTransID: res.ACSTransID, ServerID: res.ThreeDSServerTransID, Version: res.MessageVersion,
		UI: res.ACSUIType, Header: res.ChallengeInfoHeader, Text: res.ChallengeInfoText, Choices: res.ChallengeSelectInfo,
		Continue: res.OOBContinueLabel, Resend: res.ResendInformationLabel}
	if res.ChallengeCompletionInd == "Y" {
		b, _ := json.Marshal(res)
		v.Final, v.CRes = true, base64.RawURLEncoding.EncodeToString(b)
		if !strings.HasPrefix(notify, "https://") && !strings.HasPrefix(notify, "http://") {
			http.Error(w, "no notificationURL for this transaction", 400)
			return
		}
		v.NotificationURL = template.URL(notify)
	}
	if v.Header == "" && !v.Final {
		v.Header = "Verify your purchase"
	}
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action *; frame-ancestors *")
	_ = page.Execute(w, v)
}

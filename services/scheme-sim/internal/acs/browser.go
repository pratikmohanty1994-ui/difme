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
//
// FIDO (acsUiType 05, fido.go): the page first tries Secure Payment Confirmation (PaymentRequest with
// "secure-payment-confirmation", [W3C-SPC]) when SPC is offered, else navigator.credentials.get ([WEBAUTHN]); the
// requestor's iframe needs allow="payment *; publickey-credentials-get *" ([EMVCO-SPC]). The assertion posts back as
// fidoAssertion (JSON PublicKeyCredential); if the browser declines or cannot, fidoFallback=Y switches to a passcode.

// fidoJS runs the ceremony. A user cancel (NotAllowedError/AbortError) falls back to the passcode; SPC unavailable
// (no API, canMakePayment false, not allowed in the frame) tries plain WebAuthn first.
const fidoJS = `(function(){
var o=JSON.parse(document.getElementById('fido').dataset.o),fa=document.getElementById('fa'),f=fa.form;
function d(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function e(buf){var u=new Uint8Array(buf),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function j(c){if(c.toJSON){try{return JSON.stringify(c.toJSON())}catch(x){}}var r=c.response;return JSON.stringify({id:c.id,rawId:e(c.rawId),type:c.type,
 response:{clientDataJSON:e(r.clientDataJSON),authenticatorData:e(r.authenticatorData),signature:e(r.signature),userHandle:r.userHandle?e(r.userHandle):undefined},clientExtensionResults:{}})}
function fb(){document.getElementById('fb').click()}
function cancelled(x){return x&&(x.name==='NotAllowedError'||x.name==='AbortError')}
async function spc(){if(!o.spc||!window.PaymentRequest)return null;
 var r=new PaymentRequest([{supportedMethods:'secure-payment-confirmation',data:{rpId:o.rpId,credentialIds:o.credentialIds.map(d),challenge:d(o.challenge),
  instrument:o.instrument,payeeName:o.payeeName||undefined,payeeOrigin:o.payeeOrigin||undefined,timeout:o.timeout}}],{total:{label:'Total',amount:{currency:o.currency,value:o.value}}});
 if(!(await r.canMakePayment()))return null;var p=await r.show();await p.complete('success');return p.details}
function wa(){if(!window.PublicKeyCredential)return null;return navigator.credentials.get({publicKey:{challenge:d(o.challenge),rpId:o.rpId,
 allowCredentials:o.credentialIds.map(function(i){return{type:'public-key',id:d(i)}}),userVerification:'required',timeout:o.timeout}})}
document.getElementById('go').onclick=async function(){try{var c=null;try{c=await spc()}catch(x){if(cancelled(x))throw x}
 if(!c)c=await wa();if(!c)return fb();fa.value=j(c);f.submit()}catch(x){fb()}};
})();`

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
{{else if eq .UI "05"}}<div id="fido" data-o="{{.FIDO}}"></div><input type="hidden" name="fidoAssertion" id="fa">
<p><button type="button" id="go">Verify with passkey</button></p>
<p><button name="fidoFallback" value="Y" id="fb">Use a one-time code instead</button></p>
<script>` + fidoJS + `</script>
{{else}}<label>Code <input name="challengeDataEntry" inputmode="numeric" autocomplete="one-time-code" maxlength="8" autofocus></label>
<p><button>Submit</button> {{if .Resend}}<button name="resendChallenge" value="Y">{{.Resend}}</button>{{end}}</p>{{end}}
<p><button name="challengeCancel" value="01">Cancel</button></p></form>{{end}}
</body></html>`))

type view struct {
	Final                                                 bool
	NotificationURL                                       template.URL
	CRes, Session, Header, Text, ACSTransID, ServerID, UI string
	Version, Continue, Resend, FIDO                       string
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
			OOBContinue: r.PostForm.Get("oobContinue"), ChallengeCancel: r.PostForm.Get("challengeCancel"), ResendChallenge: r.PostForm.Get("resendChallenge"),
			FIDOAssertion: r.PostForm.Get("fidoAssertion"), FIDOFallback: r.PostForm.Get("fidoFallback")}
	}
	notify := a.notificationURL(r.Context(), q.ACSTransID)
	res, err := a.Challenge(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	v := view{Session: r.PostForm.Get("threeDSSessionData"), ACSTransID: res.ACSTransID, ServerID: res.ThreeDSServerTransID, Version: res.MessageVersion,
		UI: res.ACSUIType, Header: res.ChallengeInfoHeader, Text: res.ChallengeInfoText, Choices: res.ChallengeSelectInfo,
		Continue: res.OOBContinueLabel, Resend: res.ResendInformationLabel}
	if res.FIDO != nil {
		b, _ := json.Marshal(res.FIDO)
		v.FIDO = string(b)
	}
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

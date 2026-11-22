package acs_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
)

// The app channel against an independent SDK stand-in (testdata/sdk.py: jwcrypto + pyca/cryptography): it verifies
// the ACS's PS256 acsSignedContent, derives the key itself and exchanges CReq/CRes JWEs with the Go ACS, for both
// content encryptions. Skipped when python3 with jwcrypto is not installed.
func TestAppChannelJWEWithAnIndependentSDK(t *testing.T) {
	if exec.Command("python3", "-c", "import jwcrypto, cryptography").Run() != nil {
		t.Skip("python3 with jwcrypto and cryptography not installed")
	}
	sdk := func(args ...string) string {
		out, err := exec.Command("python3", append([]string{"testdata/sdk.py"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("sdk.py %s: %v\n%s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, enc := range []string{"A128CBC-HS256", "A128GCM"} {
		t.Run(enc, func(t *testing.T) {
			w := newWorld(t, acs.Alert)
			signer, err := acs.DevSigner()
			if err != nil {
				t.Fatal(err)
			}
			w.acs = acs.New(acs.Config{FrictionlessLimitMinor: 500_000, ChallengeURL: "https://acs.example/3ds/creq", PayerKey: []byte("test-key-0123456789"),
				Signer: signer}, w.cmsClient(), w.frm, w.hsm, w.otp, w.oob, w.rreqs)
			state := filepath.Join(t.TempDir(), "sdk.json")
			var pub acs.JWK
			if err := json.Unmarshal([]byte(sdk("keygen", state)), &pub); err != nil {
				t.Fatal(err)
			}
			q := areq(pan, 1000)
			q.DeviceChannel, q.SDKEphemPubKey, q.SDKReferenceNumber, q.SDKTransID = "01", &pub, "DIFME-TEST-SDK-REF-1", "sdk-1"
			res, err := w.acs.Authenticate(context.Background(), q)
			if err != nil || res.TransStatus != "C" || res.ACSSignedContent == "" || res.ACSRenderingType.Interface != "01" {
				t.Fatalf("%v %+v", err, res)
			}
			sdk("savekey", state, res.ACSSignedContent)
			creq, _ := json.Marshal(acs.CReq{MessageType: "CReq", MessageVersion: "2.3.1", ThreeDSServerTransID: "srv-1", ACSTransID: res.ACSTransID,
				SDKTransID: "sdk-1", ChallengeDataEntry: w.otp.last})
			jweCReq := sdk("creq", state, res.ACSSignedContent, enc, string(creq))
			jweCRes, err := w.acs.AppChallenge(context.Background(), jweCReq)
			if err != nil {
				t.Fatal(err)
			}
			var cres acs.CRes
			if err := json.Unmarshal([]byte(sdk("cres", state, jweCRes)), &cres); err != nil || cres.TransStatus != "Y" || cres.SDKTransID != "sdk-1" {
				t.Fatalf("CRes: %v %+v", err, cres)
			}
			// a tampered JWE is refused
			bad := jweCReq[:len(jweCReq)-3] + "AAA"
			if _, err := w.acs.AppChallenge(context.Background(), bad); err == nil {
				t.Error("tampered JWE accepted")
			}
		})
	}
}

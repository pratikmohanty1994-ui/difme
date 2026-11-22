#!/usr/bin/env bash
# ADR-027 live check, all real processes: services/hsm (jPOS, Java) <- ACS (Go) -> card management (scheme-sim card
# API); RReq to a capture endpoint standing in for the directory server; then the CAVV through the ISO adapter
# (acquirer, field 48) to the authorisation switch (scheme-sim), which verifies it with services/hsm.
# FRM is not wired here (no Tazama in this script), so the ACS challenges every authentication: the OTP path.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true; rm -rf "$W"' EXIT
[[ -x /opt/jdk25/bin/java ]] && export JAVA_HOME=/opt/jdk25 PATH=/opt/jdk25/bin:$PATH  # services/hsm targets Java 25
(cd services/hsm && mvn -q -B -DskipTests package dependency:build-classpath -Dmdep.outputFile="$W/cp" >/dev/null)
(cd services/scheme-sim && go build -o "$W/" ./cmd/scheme-sim ./cmd/acs ./cmd/iso-adapter)
HSM_DEV_INSECURE=true HSM_DEV_REBUILD_LMK=true HSM_DEV_CVK_COMPONENTS=1111111111111111FFFFFFFFFFFFFFFF,1032547698BADCFE0123456789ABCDEF HSM_ADDR=127.0.0.1:18700 \
  java -cp "services/hsm/target/classes:$(cat "$W/cp")" dev.difme.hsm.HsmServer >"$W/hsm.log" 2>&1 & pids+=($!)
EXP=$(date -d '+2 years' +%y%m); PAN=4375510000000001
HSM_URL=http://127.0.0.1:18700 ISO_LISTEN=127.0.0.1:18583 ADMIN_LISTEN=127.0.0.1:18080 HTTP_LISTEN=127.0.0.1:18080 \
  SEED_CARDS="[{\"pan\":\"$PAN\",\"expiry\":\"$EXP\",\"limitMinor\":10000000,\"status\":\"ACTIVE\"}]" "$W/scheme-sim" >"$W/sim.log" 2>&1 & pids+=($!)
NETWORK_ADDR=127.0.0.1:18583 HTTP_LISTEN=127.0.0.1:18081 "$W/iso-adapter" >"$W/adapter.log" 2>&1 & pids+=($!)
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        b=s.rfile.read(int(s.headers['content-length'])); open('$W/rreq.json','wb').write(b); s.send_response(200); s.end_headers()
    def log_message(s,*a): pass
http.server.HTTPServer(('127.0.0.1',18082),H).serve_forever()" & pids+=($!)
ACS_PAYER_KEY=dev-only-key-0123456789 ACS_ADDR=127.0.0.1:18090 ACS_CMS_URL=http://127.0.0.1:18080 HSM_URL=http://127.0.0.1:18700 \
  ACS_DS_URL=http://127.0.0.1:18082/rreq "$W/acs" >"$W/acs.log" 2>&1 & pids+=($!)
for u in 18700/healthz 18080/healthz 18081/healthz 18090/healthz; do
  for i in $(seq 60); do curl -sf "http://127.0.0.1:$u" >/dev/null && break; sleep 0.5; done
done
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -n 8 "$f"; done; exit 1; }
j() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }
echo "hsm: $(grep -o 'check value.*' "$W/hsm.log")"

ares=$(curl -s -X POST localhost:18090/3ds/areq -d "{\"messageType\":\"AReq\",\"messageVersion\":\"2.3.1\",\"messageCategory\":\"01\",\"deviceChannel\":\"02\",
 \"threeDSServerTransID\":\"srv-e2e\",\"dsTransID\":\"ds-e2e\",\"acctNumber\":\"$PAN\",\"cardExpiryDate\":\"$EXP\",\"purchaseAmount\":\"125000\",
 \"purchaseCurrency\":\"356\",\"merchantName\":\"Shop\",\"acquirerMerchantID\":\"MERCHANT01\"}")
[[ $(echo "$ares" | j transStatus) == C ]] || fail "ARes $ares"; echo "ARes: challenge"
acs=$(echo "$ares" | j acsTransID); sleep 0.3
otp=$(grep -o 'otp=[0-9]*' "$W/acs.log" | tail -1 | cut -d= -f2)
cres=$(curl -s -X POST localhost:18090/3ds/creq -d "{\"messageType\":\"CReq\",\"messageVersion\":\"2.3.1\",\"threeDSServerTransID\":\"srv-e2e\",\"acsTransID\":\"$acs\",\"challengeDataEntry\":\"$otp\"}")
[[ $(echo "$cres" | j transStatus) == Y ]] || fail "CRes $cres"; echo "CRes: Y"
cavv=$(j authenticationValue <"$W/rreq.json"); [[ -n $cavv ]] || fail "no CAVV in RReq"; echo "RReq: Y, ECI $(j eci <"$W/rreq.json"), CAVV $cavv"
pay() { curl -s -X POST localhost:18081/v1/authorize -d "{\"pan\":\"$PAN\",\"expiry\":\"$EXP\",\"amountMinor\":125000,\"merchantId\":\"MERCHANT01\",\"terminalId\":\"WEB00001\",\"cavv\":\"$1\"}" | j responseCode; }
[[ $(pay "$cavv") == 00 ]] || fail "authorisation with CAVV"; echo "authorisation with CAVV: 00 (verified by services/hsm)"
[[ $(pay "$cavv") == 05 ]] || fail "replay accepted"; echo "same CAVV again: 05 (replay)"
forged=$(python3 -c "import base64,sys; b=bytearray(base64.b64decode('$cavv')); b[5]^=0x01; print(base64.b64encode(b).decode())")
[[ $(pay "$forged") == 05 ]] || fail "forged accepted"; echo "forged CAVV: 05"
echo "acs e2e PASS"

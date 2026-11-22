#!/usr/bin/env bash
# card-issuer against a real Fineract (FINERACT, default http://127.0.0.1:8443/fineract-provider; dev basic auth) and the
# real security module (local dev keys, HSM_DEV_INSECURE: test keys only). Debit: hold, clear (withdrawal), reverse;
# credit: open-to-buy, clearing as a disbursement, a repayment in Fineract restoring the line; PIN set from an
# ISO 9564 format 4 block and PIN verification; dCVV2.
set -euo pipefail
cd "$(dirname "$0")/.."
F=${FINERACT:-http://127.0.0.1:8443/fineract-provider}; A="$F/api/v1"
H=(-s -u mifos:password -H "Fineract-Platform-TenantId: default" -H "Content-Type: application/json")
D=$(date +'%d %B %Y'); L='"locale":"en","dateFormat":"dd MMMM yyyy"'
api() { curl "${H[@]}" -X "$1" "$A/$2" ${3:+-d "$3"}; }
id() { python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1') or d.get('resourceId'); print(v) if v else sys.exit('no id: '+json.dumps([e.get('developerMessage') for e in d.get('errors',[])] or d)[:400])"; }
W=$(mktemp -d); pids=(); trap 'kill "${pids[@]}" 2>/dev/null || true; rm -rf "$W"' EXIT
fail() { echo "FAIL: $*"; tail -5 "$W"/*.log; exit 1; }
# --- Fineract: a client with a savings account (debit) and a credit line
client=$(api POST clients "{\"officeId\":1,\"legalFormId\":1,\"firstname\":\"Card\",\"lastname\":\"Holder$RANDOM\",\"active\":true,\"activationDate\":\"$D\",$L}" | id clientId)
sp=$(api POST savingsproducts "{\"name\":\"Card savings $RANDOM\",\"shortName\":\"S$((RANDOM%900+100))\",\"currencyCode\":\"INR\",\"digitsAfterDecimal\":2,\"inMultiplesOf\":0,
 \"nominalAnnualInterestRate\":0,\"interestCompoundingPeriodType\":1,\"interestPostingPeriodType\":4,\"interestCalculationType\":1,
 \"interestCalculationDaysInYearType\":365,\"accountingRule\":1,\"locale\":\"en\"}" | id resourceId)
pt=$(api POST paymenttypes '{"name":"Card network '$RANDOM'","description":"card payments","isCashPayment":false,"position":1}' | id resourceId)
sav=$(api POST savingsaccounts "{\"clientId\":$client,\"productId\":$sp,\"submittedOnDate\":\"$D\",$L}" | id savingsId)
api POST "savingsaccounts/$sav?command=approve" "{\"approvedOnDate\":\"$D\",$L}" >/dev/null
api POST "savingsaccounts/$sav?command=activate" "{\"activatedOnDate\":\"$D\",$L}" >/dev/null
api POST "savingsaccounts/$sav/transactions?command=deposit" "{\"transactionDate\":\"$D\",\"transactionAmount\":1000,\"paymentTypeId\":$pt,$L}" | id resourceId >/dev/null
terms='"numberOfRepayments":12,"repaymentEvery":1,"repaymentFrequencyType":2,"interestRatePerPeriod":0,"amortizationType":1,"interestType":0,"interestCalculationPeriodType":0,"transactionProcessingStrategyCode":"mifos-standard-strategy"'
lp=$(api POST loanproducts "{\"name\":\"Card line $RANDOM\",\"shortName\":\"L$((RANDOM%900+100))\",\"currencyCode\":\"INR\",\"digitsAfterDecimal\":2,\"inMultiplesOf\":0,
 \"principal\":500000,$terms,\"interestRateFrequencyType\":2,\"accountingRule\":1,\"daysInYearType\":1,\"daysInMonthType\":1,\"isInterestRecalculationEnabled\":false,
 \"multiDisburseLoan\":true,\"maxTrancheCount\":50,\"disallowExpectedDisbursements\":true,$L}" | id resourceId)
loan=$(api POST loans "{\"clientId\":$client,\"productId\":$lp,\"principal\":500000,\"loanTermFrequency\":12,\"loanTermFrequencyType\":2,$terms,
 \"loanType\":\"individual\",\"expectedDisbursementDate\":\"$D\",\"submittedOnDate\":\"$D\",$L}" | id loanId)
api POST "loans/$loan?command=approve" "{\"approvedOnDate\":\"$D\",\"approvedLoanAmount\":500000,$L}" >/dev/null
echo "fineract: client $client savings $sav (INR 1000) credit line loan $loan"
# --- security module (local dev keys) and card-issuer
[[ -x /opt/jdk25/bin/java ]] && export JAVA_HOME=/opt/jdk25 PATH=/opt/jdk25/bin:$PATH
(cd services/hsm && mvn -q -B -DskipTests package dependency:build-classpath -Dmdep.outputFile="$W/cp" >/dev/null)
AESPIN=00112233445566778899AABBCCDDEEFF
HSM_DEV_INSECURE=true HSM_DEV_REBUILD_LMK=true HSM_ADDR=127.0.0.1:18702 \
  HSM_DEV_KEYS="cvk=CVK;dcvv2=CVK;zpk=ZPK;pvk=PVK;aes-pin=AES/P0:$AESPIN;acs-hmac=AES/M7;acs-sign=RSA" java -cp "services/hsm/target/classes:$(cat "$W/cp")" dev.difme.hsm.HsmServer >"$W/hsm.log" 2>&1 & pids+=($!)
(cd services/card-issuer && go build -o "$W/card-issuer" ./cmd/card-issuer)
(cd services/scheme-sim && go build -o "$W/" ./cmd/scheme-sim ./cmd/iso-adapter ./cmd/acs)
ADDR=127.0.0.1:18085 HSM_URL=http://127.0.0.1:18702 FINERACT_URL="$F" FINERACT_PAYMENT_TYPE="$pt" FINERACT_USER=mifos FINERACT_PASSWORD=password "$W/card-issuer" >"$W/issuer.log" 2>&1 & pids+=($!)
for u in 18702 18085; do for i in $(seq 40); do curl -sf "localhost:$u/healthz" >/dev/null && break; sleep 1; done; done
ci() { curl -s -X "$1" "localhost:18085$2" ${3:+-d "$3"}; }
j() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1',''))"; }
bal() { api GET "savingsaccounts/$sav" | python3 -c "import json,sys; s=json.load(sys.stdin)['summary']; print(s.get('availableBalance', s['accountBalance']))"; }
# debit
deb=$(ci POST /v1/cards "{\"product\":\"DEBIT\",\"account\":$sav,\"holder\":\"partner-1\",\"channels\":[\"sms\",\"app\"]}")
pan=$(echo "$deb" | j pan); cvv=$(echo "$deb" | j cvv2); cid=$(echo "$deb" | j id); [ ${#pan} = 16 ] || fail "issue debit: $deb"
echo "debit card ${pan:0:6}******${pan:12} issued (CVV2 from the security module)"
a=$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":60000,\"currency\":\"356\",\"merchant\":\"M1\",\"cvv2\":\"$cvv\"}")
[ "$(echo "$a" | j responseCode)" = 00 ] || fail "debit auth: $a"; [ "$(bal)" = 400.0 ] || fail "hold not in Fineract: $(bal)"; echo "ok: authorised INR 600 with CVV2, hold in Fineract (available 400)"
[ "$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":50000,\"cvv2\":\"$cvv\"}" | j responseCode)" = 51 ] || fail "over balance"; echo "ok: INR 500 more declined 51"
[ "$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":100,\"cvv2\":\"999\"}" | j responseCode)" = 05 ] || fail "wrong CVV2"; echo "ok: wrong CVV2 declined 05"
ci POST "/v1/authorisations/$(echo "$a" | j id)/clear" '{"amountMinor":55000}' | j state | grep -q CLEARED || fail "clear"
[ "$(bal)" = 450.0 ] || fail "after clearing: $(bal)"; echo "ok: cleared INR 550 (withdrawal, hold released): available 450"
dc=$(ci GET "/v1/cards/$cid/dcvv2" | j dcvv2)
[ "$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":100,\"cvv2\":\"$dc\"}" | j responseCode)" = 00 ] || fail "dCVV2"; echo "ok: dynamic CVV2 $dc accepted"
# PIN from the app: ISO 9564 format 4 under the app PIN key, then a PIN-verified authorisation (network ZPK block)
iso4=$(python3 -W ignore -c "import psec.pinblock as p; print(p.encipher_pinblock_iso_4(bytes.fromhex('$AESPIN'),'2468','$pan').hex().upper())")
ci POST "/v1/cards/$cid/pin" "{\"pinBlock\":\"$iso4\"}" | grep -q "PIN set" || fail "PIN set"
blk=$(curl -s -X POST -d "{\"pan\":\"$pan\",\"pinBlock\":\"$iso4\"}" localhost:18702/v1/pin/iso4-to-zpk | j pinBlock)
[ "$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":100,\"pinBlock\":\"$blk\"}" | j responseCode)" = 00 ] || fail "PIN auth"
bad=$(python3 -W ignore -c "import psec.pinblock as p; print(p.encipher_pinblock_iso_4(bytes.fromhex('$AESPIN'),'1357','$pan').hex().upper())")
blk=$(curl -s -X POST -d "{\"pan\":\"$pan\",\"pinBlock\":\"$bad\"}" localhost:18702/v1/pin/iso4-to-zpk | j pinBlock)
[ "$(ci POST /v1/authorisations "{\"pan\":\"$pan\",\"amountMinor\":100,\"pinBlock\":\"$blk\"}" | j responseCode)" = 55 ] || fail "wrong PIN"
echo "ok: PIN set from the app (ISO-4), right PIN approved, wrong PIN declined 55"
# credit
cr=$(ci POST /v1/cards "{\"product\":\"CREDIT\",\"account\":$loan,\"limitMinor\":500000,\"holder\":\"partner-2\"}"); crp=$(echo "$cr" | j pan); crid=$(echo "$cr" | j id)
c1=$(ci POST /v1/authorisations "{\"pan\":\"$crp\",\"amountMinor\":300000}"); [ "$(echo "$c1" | j responseCode)" = 00 ] || fail "credit auth $c1"
[ "$(ci POST /v1/authorisations "{\"pan\":\"$crp\",\"amountMinor\":250000}" | j responseCode)" = 51 ] || fail "credit over limit"
ci POST "/v1/authorisations/$(echo "$c1" | j id)/clear" '{"amountMinor":300000}' | j state | grep -q CLEARED || fail "credit clear"
out=$(api GET "loans/$loan" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['principalOutstanding'])")
[ "$out" = 3000.0 ] || fail "disbursement in Fineract: $out"; echo "ok: credit INR 3000 authorised, INR 2500 over the limit declined, cleared as a Fineract disbursement"
api POST "loans/$loan/transactions?command=repayment" "{\"transactionDate\":\"$D\",\"transactionAmount\":2000,\"paymentTypeId\":$pt,$L}" >/dev/null
[ "$(ci GET "/v1/cards/$crid/open-to-buy" | j openToBuyMinor)" = 400000 ] || fail "open to buy after repayment"
[ "$(ci POST /v1/authorisations "{\"pan\":\"$crp\",\"amountMinor\":400000}" | j responseCode)" = 00 ] || fail "re-spend"
echo "ok: repayment of INR 2000 in Fineract restored the line: INR 4000 approved"
# --- the whole chain: ISO adapter (acquirer) -> switch (scheme-sim) -> issuer host (card-issuer) -> Fineract / hsm
ISSUER_URL=http://127.0.0.1:18085 HSM_URL=http://127.0.0.1:18702 ISO_LISTEN=127.0.0.1:18583 HTTP_LISTEN=127.0.0.1:18080 "$W/scheme-sim" >"$W/sim.log" 2>&1 & pids+=($!)
NETWORK_ADDR=127.0.0.1:18583 HTTP_LISTEN=127.0.0.1:18081 "$W/iso-adapter" >"$W/adapter.log" 2>&1 & pids+=($!)
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        b=s.rfile.read(int(s.headers['content-length'])); open('$W/rreq.json','wb').write(b); s.send_response(200); s.end_headers()
    def log_message(s,*a): pass
http.server.HTTPServer(('127.0.0.1',18082),H).serve_forever()" & pids+=($!)
ACS_ADDR=127.0.0.1:18090 ACS_CMS_URL=http://127.0.0.1:18085 HSM_URL=http://127.0.0.1:18702 ACS_DS_URL=http://127.0.0.1:18082/rreq "$W/acs" >"$W/acs.log" 2>&1 & pids+=($!)
for u in 18080 18081 18090; do for i in $(seq 60); do curl -sf "localhost:$u/healthz" >/dev/null && break; sleep 1; done; done
exp=$(echo "$deb" | j expiry)
pay() { curl -s -X POST localhost:18081/v1/authorize -d "{\"pan\":\"$pan\",\"expiry\":\"$exp\",\"amountMinor\":$1,\"merchantId\":\"MERCHANT01\",\"terminalId\":\"WEB00001\",$2}" | j responseCode; }
b0=$(bal); [ "$(pay 10000 '"cvv2":"'"$cvv"'","capture":true')" = 00 ] || fail "purchase through the switch"
[ "$(bal)" = "$(python3 -c "print($b0-100.0)")" ] || fail "purchase not posted in Fineract: $b0 -> $(bal)"
echo "ok: purchase through ISO adapter -> switch -> card-issuer: INR 100 withdrawn in Fineract ($b0 -> $(bal))"
[ "$(pay 10000 '"cvv2":"000"')" = 05 ] || fail "wrong CVV2 through the switch"; echo "ok: wrong CVV2 through the switch declined 05"
# 3-D Secure: the ACS reads the card from card-issuer (channels sms+app: out-of-band app approval), CAVV checked at the switch
ares=$(curl -s -X POST localhost:18090/3ds/areq -d "{\"messageType\":\"AReq\",\"messageVersion\":\"2.3.1\",\"messageCategory\":\"01\",\"deviceChannel\":\"02\",
 \"threeDSServerTransID\":\"srv-live\",\"dsTransID\":\"ds-live\",\"acctNumber\":\"$pan\",\"cardExpiryDate\":\"$exp\",\"purchaseAmount\":\"20000\",
 \"purchaseCurrency\":\"356\",\"merchantName\":\"Shop\",\"acquirerMerchantID\":\"MERCHANT01\"}")
acsid=$(echo "$ares" | j acsTransID); [ "$(echo "$ares" | j authenticationType)" = 03 ] || fail "expected out-of-band (app enrolled): $ares"
curl -s -X POST "localhost:18090/3ds/oob/$acsid" -d '{"approved":true}' >/dev/null
cres=$(curl -s -X POST localhost:18090/3ds/creq -d "{\"messageType\":\"CReq\",\"messageVersion\":\"2.3.1\",\"threeDSServerTransID\":\"srv-live\",\"acsTransID\":\"$acsid\",\"oobContinue\":\"Y\"}")
[ "$(echo "$cres" | j transStatus)" = Y ] || fail "OOB: $cres"; cavv=$(j authenticationValue <"$W/rreq.json")
[ "$(pay 20000 '"cavv":"'"$cavv"'"')" = 00 ] || fail "CAVV payment through the switch"
[ "$(pay 20000 '"cavv":"'"$cavv"'"')" = 05 ] || fail "CAVV replay"
echo "ok: 3-D Secure 2.3.1 out-of-band approval (ACS reads card-issuer), CAVV verified at the switch, replay declined"
echo "card-issuer live PASS"

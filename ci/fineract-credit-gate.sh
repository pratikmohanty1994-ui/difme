#!/usr/bin/env bash
# ADR-025 gate: can an Apache Fineract multi-disbursement loan carry a credit-card line? Run against a Fineract with a
# default tenant (FINERACT, default http://127.0.0.1:8443/fineract-provider; dev basic auth mifos/password).
#  1. Native limit: maxOutstandingLoanBalance. Fineract checks it against the *scheduled* balance (repayments are not
#     counted) and only for tranches after the schedule's first period start, so it cannot act as a revolving limit.
#     The gate asserts that behaviour, so a Fineract upgrade that changes it shows up here.
#  2. Fallback (the design): the card-issuer service enforces open-to-buy = limit - actual principal outstanding
#     (Fineract's loan summary) before each disbursement; Fineract books spends, repayments and the balance.
set -uo pipefail
F=${FINERACT:-http://127.0.0.1:8443/fineract-provider}/api/v1
H=(-s -u mifos:password -H "Fineract-Platform-TenantId: default" -H "Content-Type: application/json")
d() { date -d "$1 days ago" +'%d %B %Y'; }; L='"locale":"en","dateFormat":"dd MMMM yyyy"'
api() { curl "${H[@]}" -X "$1" "$F/$2" ${3:+-d "$3"}; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1') or d.get('resourceId'); print(v or ''); v or print(json.dumps(d.get('errors',d))[:600], file=sys.stderr)"; }
fails=0; check() { [[ $2 == "$3" ]] && echo "PASS $1 ($2)" || { echo "FAIL $1: got $2, want $3"; fails=$((fails+1)); }; }
outstanding() { api GET "loans/$1" | python3 -c "import json,sys; print(float(json.load(sys.stdin).get('summary',{}).get('principalOutstanding',0)))"; }
client=$(api POST clients "{\"officeId\":1,\"legalFormId\":1,\"firstname\":\"Card\",\"lastname\":\"Holder\",\"active\":true,\"activationDate\":\"$(d 30)\",$L}" | field clientId)
terms='"numberOfRepayments":12,"repaymentEvery":1,"repaymentFrequencyType":2,"interestRatePerPeriod":0,"amortizationType":1,"interestType":0,"interestCalculationPeriodType":0,"transactionProcessingStrategyCode":"mifos-standard-strategy"'
product() { api POST loanproducts "{\"name\":\"Credit line $RANDOM\",\"shortName\":\"C$((RANDOM%900+100))\",\"currencyCode\":\"INR\",\"digitsAfterDecimal\":2,\"inMultiplesOf\":0,
 \"principal\":500000,$terms,\"interestRateFrequencyType\":2,\"accountingRule\":1,\"daysInYearType\":1,\"daysInMonthType\":1,\"isInterestRecalculationEnabled\":false,
 \"multiDisburseLoan\":true,\"maxTrancheCount\":50,$1\"disallowExpectedDisbursements\":true,$L}" | field resourceId; }
# A line with a large approved principal (lifetime disbursement ceiling) and, optionally, Fineract's own max outstanding.
line() { local p=$1 loan; loan=$(api POST loans "{\"clientId\":$client,\"productId\":$p,\"principal\":500000,\"loanTermFrequency\":12,\"loanTermFrequencyType\":2,$terms,
 \"loanType\":\"individual\",$2\"expectedDisbursementDate\":\"$(d 10)\",\"submittedOnDate\":\"$(d 10)\",$L}" | field loanId)
  api POST "loans/$loan?command=approve" "{\"approvedOnDate\":\"$(d 10)\",\"approvedLoanAmount\":500000,$L}" >/dev/null; echo "$loan"; }
disburse() { api POST "loans/$1?command=disburse" "{\"actualDisbursementDate\":\"$(d "$2")\",\"transactionAmount\":$3,$L}" | grep -q '"resourceId"' && echo ok || echo refused; }
repay() { api POST "loans/$1/transactions?command=repayment" "{\"transactionDate\":\"$(d "$2")\",\"transactionAmount\":$3,$L}" | grep -q '"resourceId"' && echo ok || echo refused; }

echo "== 1. Fineract's maxOutstandingLoanBalance (5000)"
n=$(line "$(product '"outstandingLoanBalance":5000,')" '"maxOutstandingLoanBalance":5000,')
check "spend 3000" "$(disburse "$n" 9 3000)" ok
check "repay 2000 (actual outstanding 1000)" "$(repay "$n" 8 2000)" ok
check "spend 2500: refused although actual outstanding would be 3500 (repayment ignored)" "$(disburse "$n" 6 2500)" refused

echo "== 2. Issuer-enforced open-to-buy on the Fineract balance (limit 5000)"
LIMIT=5000; n=$(line "$(product '')" '')
spend() { local o; o=$(outstanding "$n"); if python3 -c "import sys; sys.exit(0 if $o + $3 <= $LIMIT else 1)"; then disburse "$n" "$2" "$3"; else echo refused; fi; }
check "spend 3000" "$(spend "$n" 9 3000)" ok
check "repay 2000" "$(repay "$n" 8 2000)" ok
check "outstanding" "$(outstanding "$n")" 1000.0
check "spend 2500 again (outstanding 3500)" "$(spend "$n" 6 2500)" ok
check "spend 2000 more (would be 5500 > 5000)" "$(spend "$n" 4 2000)" refused
check "spend 1500 (exactly at the limit)" "$(spend "$n" 2 1500)" ok
check "outstanding" "$(outstanding "$n")" 5000.0
check "repay 5000 (cleared)" "$(repay "$n" 1 5000)" ok
check "outstanding" "$(outstanding "$n")" 0.0
[[ $fails == 0 ]] && echo "credit gate PASS" || { echo "credit gate FAIL ($fails)"; exit 1; }

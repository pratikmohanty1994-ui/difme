#!/usr/bin/env python3
"""Cross-bank payment through the Mojaloop switch on the deployed rails profile (the cluster counterpart of the
2026-11-21 local money test, D3 e).

A DIFME account pays party MSISDN 919900000001 at the other bank (payeefsp: SDK scheme adapter + simulator,
deploy/platform/rails/mojaloop-switch):
  PH-EE channel /channel/transfer (payee without fspId -> PayerFundTransfer, Mifos's own flow on Fluxnova)
  -> party lookup, quote and transfer through the switch -> payeefsp COMMITTED -> payer booked in Fineract.
Checks: the flow ends at "Transfer successfully completed" and the payer's Fineract balance dropped by the amount.

The payer is a dedicated check account, "xbank-check", funded through the interim payment hub (which creates Fineract
accounts with their ACCOUNT_ID interop identifier on first use). Port-forwards: payment hub, PH-EE channel, Fluxnova
(Basic login from Secret rails/fluxnova). Exit 1 on a failed check."""
import base64
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HUB, CHANNEL, FLUX = 18190, 18180, 18188
PAYER, PAYEE_MSISDN, AMOUNT_MINOR = "xbank-check", "919900000001", 150
SUCCESS_END = "EndEvent_1y60c95"   # PayerFundTransfer: "Transfer successfully completed"


def kubectl(*args):
    return subprocess.run(["kubectl", *args], capture_output=True, text=True).stdout.strip()


def forward(ns, target, local, remote):
    p = subprocess.Popen(["kubectl", "-n", ns, "port-forward", target, f"{local}:{remote}"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", local), timeout=1).close()
            return p
        except OSError:
            time.sleep(0.2)
    return p


def call(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            txt = r.read().decode()
            return r.status, json.loads(txt) if txt.strip() else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]
    except OSError as e:
        return 0, str(e)


def balance():
    code, b = call("GET", f"http://127.0.0.1:{HUB}/v1/accounts/{PAYER}")
    return b.get("balanceMinor") if code == 200 and isinstance(b, dict) else None


def main():
    basic = kubectl("-n", "rails", "get", "secret", "fluxnova", "-o", "jsonpath={.data.admin-basic}")
    if not basic:
        print("  mojaloop cross-bank: FAILED - no Secret rails/fluxnova")
        return 1
    flux_auth = "Basic " + base64.b64encode(base64.b64decode(basic)).decode()
    pfs = [forward("rails", "svc/payment-hub", HUB, 8090), forward("rails", "deploy/ph-ee-connector-channel", CHANNEL, 8080),
           forward("process", "svc/fluxnova", FLUX, 8080)]
    try:
        return run(flux_auth)
    finally:
        for p in pfs:
            p.terminate()


def run(flux_auth):
    run_id = uuid.uuid4().hex[:12]
    # 1. fund the payer (creates it, with its ACCOUNT_ID identifier, on first use)
    code, r = call("POST", f"http://127.0.0.1:{HUB}/v1/accounts/{PAYER}/deposits", {"depositId": "xbank-fund-" + run_id, "amountMinor": 10_000})
    before = balance()
    print(f"  mojaloop cross-bank: payer {PAYER} funded (HTTP {code}), balance {before}")
    if before is None:
        print("  mojaloop cross-bank: FAILED - payer account not readable")
        return 1
    # 2. pay the other bank's party through PH-EE (no payee fspId: the switch's lookup finds payeefsp)
    corr = "xbank-" + run_id
    body = {"payer": {"partyIdInfo": {"partyIdType": "ACCOUNT_ID", "partyIdentifier": PAYER}},
            "payee": {"partyIdInfo": {"partyIdType": "MSISDN", "partyIdentifier": PAYEE_MSISDN}},
            "amount": {"amount": f"{AMOUNT_MINOR / 100:.2f}", "currency": "INR"}, "note": "cluster cross-bank check"}
    code, r = call("POST", f"http://127.0.0.1:{CHANNEL}/channel/transfer", body,
                   {"Platform-TenantId": "default", "X-CorrelationID": corr})
    if code // 100 != 2:
        print(f"  mojaloop cross-bank: FAILED - channel answered {code}: {r}")
        return 1
    # 3. follow the PayerFundTransfer instance in Fluxnova's history
    q = urllib.parse.urlencode({"processDefinitionKey": "PayerFundTransfer-default", "variables": "clientCorrelationId_eq_" + corr})
    state, pid, deadline = "", None, time.time() + 120
    while time.time() < deadline:
        code, l = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/process-instance?{q}", headers={"Authorization": flux_auth})
        if code == 200 and l:
            pid, state = l[0]["id"], l[0]["state"]
            if state != "ACTIVE":
                break
        time.sleep(3)
    end = ""
    if pid:
        code, ends = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/activity-instance?processInstanceId={pid}&activityType=noneEndEvent",
                          headers={"Authorization": flux_auth})
        end = ends[0]["activityId"] if code == 200 and ends else ""
        code, acts = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/activity-instance?processInstanceId={pid}&sortBy=startTime&sortOrder=asc",
                          headers={"Authorization": flux_auth})
        steps = " > ".join(a.get("activityName") or a["activityId"] for a in acts if a.get("activityType") in ("serviceTask", "receiveTask", "intermediateCatchEvent")) if code == 200 and acts else ""
        print(f"  mojaloop cross-bank: PayerFundTransfer {pid} {state or '-'} end {end or '-'}; steps: {steps[:400]}")
    else:
        print("  mojaloop cross-bank: no PayerFundTransfer instance for " + corr)
    after = None
    for _ in range(10):
        after = balance()
        if after is not None and before - after == AMOUNT_MINOR:
            break
        time.sleep(2)
    print(f"  mojaloop cross-bank: payer balance {before} -> {after} (expected -{AMOUNT_MINOR})")
    ok = end == SUCCESS_END and after is not None and before - after == AMOUNT_MINOR
    print("  mojaloop cross-bank: " + ("ok" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

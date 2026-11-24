#!/usr/bin/env python3
"""Cross-bank payment through the Mojaloop switch on the deployed rails profile (the cluster counterpart of the
2026-11-21 local money test, D3 e).

A DIFME account pays party MSISDN 919900000001 at the other bank (payeefsp: SDK scheme adapter + simulator,
deploy/platform/rails/mojaloop-switch):
  PH-EE channel /channel/transfer (payee without fspId -> PayerFundTransfer, Mifos's own flow on Fluxnova)
  -> party lookup, quote and transfer through the switch -> payeefsp COMMITTED -> payer booked in Fineract.
Checks: the flow ends at "Transfer successfully completed" and the payer's Fineract balance dropped by the amount.

The payer is a dedicated check account, "xbank-check", opened through PH-EE's DifmeOpenAccount flow (rails-worker:
Fineract account + ACCOUNT_ID) and funded with an on-us transfer from card-settlement (a settlement account, may run
negative) through the channel: no interim hub involved. Balances are read from Fineract (Keycloak client credentials
from Secret rails/fineract-admin-oauth). Port-forwards: PH-EE channel, Fluxnova (Basic login from Secret
rails/fluxnova), Fineract, Keycloak. Exit 1 on a failed check."""
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

CHANNEL, FLUX, FINERACT, KEYCLOAK = 18180, 18188, 18191, 18192
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


TOKEN = {}


def secret(ns, name, key):
    v = kubectl("-n", ns, "get", "secret", name, "-o", "jsonpath={.data." + key + "}")
    return base64.b64decode(v).decode() if v else ""


def fineract_token():
    if "h" not in TOKEN:
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": secret("rails", "fineract-admin-oauth", "client-id"),
                                       "client_secret": secret("rails", "fineract-admin-oauth", "client-secret")}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{KEYCLOAK}/realms/difme/protocol/openid-connect/token", data=form,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=20) as r:
            TOKEN["h"] = "Bearer " + json.loads(r.read())["access_token"]
    return TOKEN["h"]


def balance():
    """The payer's Fineract balance in minor units, or None."""
    try:
        h = {"Authorization": fineract_token(), "Fineract-Platform-TenantId": "default"}
    except OSError as e:
        print(f"  mojaloop cross-bank: no Fineract token: {e}")
        return None
    code, a = call("GET", f"http://127.0.0.1:{FINERACT}/fineract-provider/api/v1/savingsaccounts/external-id/{PAYER}", headers=h)
    if code != 200 or not isinstance(a, dict):
        return None
    code, a = call("GET", f"http://127.0.0.1:{FINERACT}/fineract-provider/api/v1/savingsaccounts/{a['id']}", headers=h)
    return round(float(a["summary"]["accountBalance"]) * 100) if code == 200 and isinstance(a, dict) else None


def flow_end(flux_auth, definition, query):
    """(instance id, state, end event id) of the newest instance matching query, waiting up to 2 minutes for it to end."""
    q = urllib.parse.urlencode({"processDefinitionKey": definition, **query})
    pid, state, deadline = None, "", time.time() + 120
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
    return pid, state, end


def steps(flux_auth, pid):
    """The instance's task/wait steps in order, with the one still open marked."""
    code, acts = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/activity-instance?processInstanceId={pid}&sortBy=startTime&sortOrder=asc",
                      headers={"Authorization": flux_auth})
    if code != 200 or not acts:
        return ""
    return " > ".join((a.get("activityName") or a["activityId"]) + ("" if a.get("endTime") else " (open)") for a in acts
                      if a.get("activityType") in ("serviceTask", "receiveTask", "intermediateCatchEvent", "intermediateMessageCatch"))


def open_account(flux_auth, name):
    """Opens the account through DifmeOpenAccount (the exchange's way); True when Fineract has it with its ACCOUNT_ID."""
    bk = "open-" + name
    code, l = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/process-instance?" + urllib.parse.urlencode(
        {"processDefinitionKey": "DifmeOpenAccount-default", "processInstanceBusinessKey": bk}), headers={"Authorization": flux_auth})
    if not (code == 200 and l):
        code, r = call("POST", f"http://127.0.0.1:{FLUX}/engine-rest/process-definition/key/DifmeOpenAccount-default/start",
                       {"businessKey": bk, "variables": {"accountName": {"value": name, "type": "String"}}}, {"Authorization": flux_auth})
        if code // 100 != 2:
            print(f"  mojaloop cross-bank: DifmeOpenAccount {name}: start answered {code}: {r}")
            return False
    pid, state, end = flow_end(flux_auth, "DifmeOpenAccount-default", {"processInstanceBusinessKey": bk})
    code, v = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/variable-instance?processInstanceId={pid}&variableName=accountStatus",
                   headers={"Authorization": flux_auth}) if pid else (0, None)
    status = v[0]["value"] if code == 200 and v else "-"
    print(f"  mojaloop cross-bank: DifmeOpenAccount {name}: {state or 'no instance'}, accountStatus {status}")
    return status == "open"


def channel_transfer(corr, payer, payee_type, payee, fsp=None):
    payee_info = {"partyIdType": payee_type, "partyIdentifier": payee}
    if fsp:
        payee_info["fspId"] = fsp
    body = {"payer": {"partyIdInfo": {"partyIdType": "ACCOUNT_ID", "partyIdentifier": payer}}, "payee": {"partyIdInfo": payee_info},
            "amount": {"amount": f"{AMOUNT_MINOR / 100:.2f}" if payee_type == "MSISDN" else "100.00", "currency": "INR"},
            "note": "cluster cross-bank check"}
    return call("POST", f"http://127.0.0.1:{CHANNEL}/channel/transfer", body, {"Platform-TenantId": "default", "X-CorrelationID": corr})


def main():
    basic = kubectl("-n", "rails", "get", "secret", "fluxnova", "-o", "jsonpath={.data.admin-basic}")
    if not basic:
        print("  mojaloop cross-bank: FAILED - no Secret rails/fluxnova")
        return 1
    flux_auth = "Basic " + base64.b64encode(base64.b64decode(basic)).decode()
    pfs = [forward("rails", "deploy/ph-ee-connector-channel", CHANNEL, 8080), forward("process", "svc/fluxnova", FLUX, 8080),
           forward("rails", "svc/fineract", FINERACT, 8080), forward("security", "svc/keycloak", KEYCLOAK, 8080)]
    try:
        return run(flux_auth)
    finally:
        for p in pfs:
            p.terminate()


def run(flux_auth):
    run_id = uuid.uuid4().hex[:12]
    # 1. open the payer and the funding account through PH-EE, then fund the payer with an on-us transfer
    if not (open_account(flux_auth, "card-settlement") and open_account(flux_auth, PAYER)):
        print("  mojaloop cross-bank: FAILED - accounts not opened through DifmeOpenAccount")
        return 1
    fund = "xbank-fund-" + run_id
    code, r = channel_transfer(fund, "card-settlement", "ACCOUNT_ID", PAYER, "default")
    fpid, fstate, fend = flow_end(flux_auth, "DifmeOnUsTransfer-default", {"variables": "clientCorrelationId_eq_" + fund}) if code // 100 == 2 else (None, "", "")
    if fpid and fend != "done":
        print(f"  mojaloop cross-bank: DifmeOnUsTransfer steps: {steps(flux_auth, fpid)}")
    before = balance()
    print(f"  mojaloop cross-bank: payer funded on-us (channel {code}, DifmeOnUsTransfer {fstate or '-'} end {fend or '-'}), balance {before}")
    if before is None:
        print("  mojaloop cross-bank: FAILED - payer balance not readable from Fineract")
        return 1
    # 2. pay the other bank's party through PH-EE (no payee fspId: the switch's lookup finds payeefsp)
    corr = "xbank-" + run_id
    code, r = channel_transfer(corr, PAYER, "MSISDN", PAYEE_MSISDN)
    if code // 100 != 2:
        print(f"  mojaloop cross-bank: FAILED - channel answered {code}: {r}")
        return 1
    # 3. follow the PayerFundTransfer instance in Fluxnova's history
    pid, state, end = flow_end(flux_auth, "PayerFundTransfer-default", {"variables": "clientCorrelationId_eq_" + corr})
    if pid:
        print(f"  mojaloop cross-bank: PayerFundTransfer {pid} {state or '-'} end {end or '-'}; steps: {steps(flux_auth, pid)[:400]}")
        code, v = call("GET", f"http://127.0.0.1:{FLUX}/engine-rest/history/variable-instance?processInstanceId={pid}", headers={"Authorization": flux_auth})
        if code == 200 and v and end != SUCCESS_END:
            hints = {x["name"]: str(x.get("value"))[:160] for x in v if any(k in x["name"].lower() for k in ("error", "fail", "state", "fsp"))}
            print(f"  mojaloop cross-bank: flow variables: {hints}"[:600])
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

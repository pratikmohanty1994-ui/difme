#!/usr/bin/env python3
"""End-to-end Tazama check against the deployed fraud profile (the cluster counterpart of ci/tazama-e2e.sh).

Sends real messages to the deployed TMS (kubectl port-forward) and reads Tazama's verdicts from its evaluation database
(tazama_evaluation on postgres-docdb, through kubectl exec):
  1. a payment: pacs.008 + pacs.002 with a fresh EndToEndId -> evaluated with both payment typologies
     (difme-901-902: velocity rules 901/902; difme-fraud-model: DIFME's ONNX model as rule D01);
  2. a 3-D Secure authentication as the ACS sends it (services/scheme-sim/internal/acs/tazama/pain001.json) -> scored by
     difme-3ds-risk only, so velocity rules and D02 never count an authentication as a payment (ADR-027).
Exact scores depend on the deployed fraud scorer and on earlier traffic, so they are printed, not asserted (the local
test, with a fixed stand-in scorer and an empty database, asserts them). Exit 1 on a failed check.

Templates: ci/tazama/pacs008.json and pacs002.json (frms-coe-lib's test samples, extracted), the ACS's pain.001."""
import json
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = 13000
TMS = f"http://127.0.0.1:{PORT}/v1/evaluate/iso20022/"


def new_id():
    return uuid.uuid4().hex


def post(kind, body):
    req = urllib.request.Request(TMS + kind, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return f"{e.code} {e.read().decode()[:200]}"


def psql(sql):
    r = subprocess.run(["kubectl", "-n", "database-tier", "exec", "postgres-docdb-0", "-c", "postgres", "--",
                        "psql", "-U", "difme", "-d", "tazama_evaluation", "-tAc", sql], capture_output=True, text=True)
    return r.stdout.strip()


def typologies(e2e, tries=30):
    """'cfg=result' per typology of the evaluation that mentions e2e, sorted; '' when none arrived."""
    sql = (f"select string_agg(t->>'cfg' || '=' || (t->>'result'), ' ' order by t->>'cfg') from evaluation, "
           f"jsonb_array_elements(evaluation->'report'->'tadpResult'->'typologyResult') t where evaluation::text like '%{e2e}%'")
    for _ in range(tries):
        out = psql(sql)
        if out:
            return out
        time.sleep(2)
    return ""


def status(e2e):
    return psql(f"select evaluation->'report'->>'status' from evaluation where evaluation::text like '%{e2e}%' limit 1")


def main():
    pf = subprocess.Popen(["kubectl", "-n", "fraud", "port-forward", "svc/tazama-tms", f"{PORT}:3000"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        return run()
    finally:
        pf.terminate()


def run():
    ok = True
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    # 1. payment
    e2e = new_id()
    a = json.loads((ROOT / "ci/tazama/pacs008.json").read_text())
    b = json.loads((ROOT / "ci/tazama/pacs002.json").read_text())
    a["FIToFICstmrCdtTrf"]["GrpHdr"].update({"MsgId": new_id(), "CreDtTm": now})
    a["FIToFICstmrCdtTrf"]["CdtTrfTxInf"]["PmtId"]["EndToEndId"] = e2e
    b["FIToFIPmtSts"]["GrpHdr"].update({"MsgId": new_id(), "CreDtTm": now})
    b["FIToFIPmtSts"]["TxInfAndSts"]["OrgnlEndToEndId"] = e2e
    for kind, msg in (("pacs.008.001.10", a), ("pacs.002.001.12", b)):
        code = post(kind, msg)
        if code != 200:
            print(f"  tazama payment: FAILED - TMS answered {code} to {kind}")
            return 1
        time.sleep(2)
    got = typologies(e2e)
    cfgs = sorted(x.split("=")[0] for x in got.split()) if got else []
    want = ["difme-901-902@1.0.0", "difme-fraud-model@1.0.0"]
    print(f"  tazama payment {e2e}: status {status(e2e) or '-'}, typologies {got or 'none'}")
    if cfgs != want:
        print(f"  tazama payment: FAILED - expected typologies {want}")
        ok = False
    # 2. 3-D Secure authentication (pain.001), as the ACS sends it
    e3 = "acs-" + new_id()
    p = json.loads((ROOT / "services/scheme-sim/internal/acs/tazama/pain001.json").read_text())
    p.pop("TenantId", None)
    p["CstmrCdtTrfInitn"]["GrpHdr"].update({"MsgId": new_id(), "CreDtTm": now})
    p["CstmrCdtTrfInitn"]["PmtInf"]["CdtTrfTxInf"]["PmtId"]["EndToEndId"] = e3
    code = post("pain.001.001.11", p)
    if code != 200:
        print(f"  tazama 3DS: FAILED - TMS answered {code} to pain.001")
        return 1
    got3 = typologies(e3)
    cfgs3 = sorted(x.split("=")[0] for x in got3.split()) if got3 else []
    print(f"  tazama 3DS {e3}: typologies {got3 or 'none'}")
    if cfgs3 != ["difme-3ds-risk@1.0.0"]:
        print("  tazama 3DS: FAILED - expected difme-3ds-risk only (no double counting of authentications)")
        ok = False
    print("  tazama end to end: " + ("ok" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

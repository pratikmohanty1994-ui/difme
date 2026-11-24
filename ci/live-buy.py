#!/usr/bin/env python3
"""Live buy smoke through the shopbot PWA's own web server (its /api proxy to exchange-svc), the path a phone takes:
standing mandate -> intent -> auction -> execute -> evidence -> simulated delivery. Prints one line per step; exit 1 on
the first failure. Reaches the PWA through `kubectl port-forward` (the API server's service proxy can't send JSON
bodies: `kubectl create --raw` got 415 from the exchange)."""
import json, subprocess, sys, time, urllib.error, urllib.request

PORT = 18080
BASE = f"http://127.0.0.1:{PORT}/api/v1/exchange"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path}: HTTP {e.code} {e.read().decode()[:300]}") from None
    return json.loads(text) if text.strip() else {}


def main():
    pf = subprocess.Popen(["kubectl", "-n", "core-platform", "port-forward", "svc/pwa-shopbot", f"{PORT}:8080"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1).read()
                break
            except OSError:
                time.sleep(0.2)
        live_buy()
        fail_path()
    finally:
        pf.terminate()


class BeforeExecute(RuntimeError):
    """Failed before the purchase was executed: nothing was bought, so one retry is safe."""


def live_buy():
    """One retry when the attempt failed before execute (the auction's short bid window can close on a busy node
    before the standing bids are in); a failure at or after execute is reported at once. Exit 1 when it fails."""
    for attempt in (1, 2):
        try:
            run(attempt)
            print("  live buy: ok" + (" (on the retry)" if attempt == 2 else ""))
            return True
        except BeforeExecute as ex:
            print(f"  live buy attempt {attempt}: {ex}")
            if attempt == 2:
                print(f"  live buy: FAILED - {ex}")
        except Exception as ex:  # noqa: BLE001 - smoke reports any failure the same way
            print(f"  live buy: FAILED - {ex}")
            break
    sys.exit(1)


def run(attempt):
    t0 = time.time()
    step = lambda msg: print(f"  {time.time() - t0:5.1f}s {msg}")
    try:
        m = call("POST", "/fr01-buy/mandates", {"partnerRef": f"smoke-{int(t0)}-{attempt}", "limitMinor": 1600000, "maxPerOrderMinor": 1600000,
                 "minYieldPct": 4, "depositMinor": 1200000, "budgetTotalMinor": 1600000, "merchantCount": 2, "goodsCount": 5,
                 "validityDays": 5, "cardJurisdiction": "IN_DOMESTIC_AFA"})
        step(f"standing mandate {m['mandateId']} registered")
        o = call("POST", "/fr01-buy/intents", {"riskScore": 900, "offerSanctioned": True, "listMinor": 2000000, "discountBps": 2000,
                 "feeMinor": 20000, "maxPriceMinor": 1900000})
        aid = o["auctionId"]
        step(f"intent accepted: auction {aid}, standing bids {o.get('standingBids')}")
        r = {}
        for _ in range(100):
            r = call("GET", f"/auctions/{aid}")
            if r.get("award") or r.get("status") != "OPEN" and "ranked" in r:
                break
            time.sleep(0.1)
        if not r.get("award"):
            raise BeforeExecute(f"no award: {json.dumps(r)[:200]}")
        s = r["award"]["split"]
        step(f"awarded to node {r['award']['winner']['nodeRef']}: A {s['a']} Y {s['yield']} F {s['fee']} buyer pays {s['b']}")
        e = call("POST", f"/auctions/{aid}/execute", {"merchantId": "m-smoke"})
        if not e.get("fulfilled"):
            raise RuntimeError(f"not bought: {json.dumps(e)[:200]}")
        step(f"bought by node {e['boughtBy']}, escrow {e['escrow']['state']}")
        ev = call("GET", f"/auctions/{aid}/evidence")
        v = ev["verdict"]
        step(f"evidence: hashes {v['hashes']} links {v['links']} seal {v['seal']} witnesses {v['witnesses']}")
        f = call("POST", f"/auctions/{aid}/sim/delivery")
        if not f.get("verified"):
            raise RuntimeError(f"delivery refused: {f.get('problems')}")
        step(f"delivered: escrow released {f['escrow']['releasedMinor']} of {f['escrow']['heldMinor']}, yield after the return window")
    except (BeforeExecute, RuntimeError):
        raise
    except (KeyError, TypeError, ValueError) as ex:
        raise RuntimeError(f"unexpected answer: {ex!r}") from None


def fail_path():
    """§11.1 FAIL path, only with the ml profile's scorer deployed: an intent with raw features and no client score is
    scored by the exchange itself. Reported on its own line (informational): a scorer problem is not a live buy failure."""
    if subprocess.run(["kubectl", "-n", "ml-platform", "get", "svc", "onnx-serving"], capture_output=True).returncode != 0:
        return
    feats = {"amountZscore": 0.2, "txnCount1h": 1, "distinctCounterparties24h": 2, "geoJumpKm1h": 3, "newDeviceFlag": 0,
             "edgeScoreMean24h": 860}
    try:
        o = call("POST", "/fr01-buy/intents", {"riskScore": 0, "offerSanctioned": True, "listMinor": 2000000, "discountBps": 2000,
                 "feeMinor": 20000, "maxPriceMinor": 1900000, "fraudFeatures": feats})
    except Exception as ex:  # noqa: BLE001
        print(f"  server-side scoring: FAILED - intent with raw features refused: {ex}")
        return
    src = str(o.get("riskSource", ""))
    if src.startswith("server:"):
        print(f"  server-side scoring: ok (auction {o.get('auctionId')}, {src})")
    else:
        # The exchange fell back (scorer unreachable or not configured): say which, so it isn't read as a pass.
        print(f"  server-side scoring: FAILED - scored by '{src or 'nothing'}' instead of the server model "
              f"(onnx-serving deployed; check exchange-svc's scorer URL and the scorer's logs)")


main()

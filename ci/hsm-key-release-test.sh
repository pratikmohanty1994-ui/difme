#!/usr/bin/env bash
# ADR-026: the security module gets its keys only through attested key release. Real Trustee (KBS + AS + RVPS, the
# staged images in Trustee's docker-compose) with DIFME's dev attestation policy and resource policy; a stand-in for
# OpenBao's create-only role that stores into the KBS (as Trustee's vault_kv backend reads OpenBao in the cluster).
# Expected: first start generates keys inside the module (stored create-only); a restart gets the same keys back by
# attestation; a changed measurement and a missing KBS both stop the module from starting.
# Needs: docker compose, a Trustee checkout ($TRUSTEE_DIR), JDK 25, Maven.
set -euo pipefail
: "${TRUSTEE_DIR:?Trustee checkout}"
here=$(cd "$(dirname "$0")/.." && pwd); pol=$here/deploy/platform/security/tee-key-release
W=$(mktemp -d); pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; (cd "$W" && docker compose down -v >/dev/null 2>&1) || true; rm -rf "$W"; }
trap cleanup EXIT
[[ -x /opt/jdk25/bin/java ]] && export JAVA_HOME=/opt/jdk25 PATH=/opt/jdk25/bin:$PATH
(cd "$here/services/hsm" && mvn -q -B -DskipTests package dependency:build-classpath -Dmdep.outputFile="$W/cp" >/dev/null)
CP="$here/services/hsm/target/classes:$(cat "$W/cp")"
mkdir -p "$W/kbs/config" "$W/kbs/data" "$W/run"; cp "$TRUSTEE_DIR/docker-compose.yml" "$W/"; cp -r "$TRUSTEE_DIR/kbs/config/docker-compose" "$W/kbs/config/"
(cd "$W" && docker compose up -d --no-build >/dev/null 2>&1)
for i in $(seq 60); do curl -s -o /dev/null localhost:8080/kbs/v0/auth && break; sleep 2; done; sleep 3
T=$(cat "$W/kbs/config/docker-compose/admin-token"); b64u() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
adm() { curl -sf -o /dev/null -H "Authorization: Bearer $T" -H 'content-type: application/json' "$@"; }
adm -d "{\"type\":\"rego\",\"policy_id\":\"default_cpu\",\"policy\":\"$(b64u <"$pol/attestation-policy.dev.rego")\"}" localhost:8080/kbs/v0/attestation-policy
adm -d "{\"policy\":\"$(b64u <"$pol/resource-policy.rego")\"}" localhost:8080/kbs/v0/resource-policy
adm -d "{\"version\":\"0.1.0\",\"type\":\"sample\",\"payload\":\"$(printf '{"difme_hsm_measurement":["1"]}' | base64 -w0)\"}" localhost:8080/kbs/v0/reference-value
# OpenBao stand-in: Kubernetes login, then create-only writes under kbs/difme/hsm/*, stored into the KBS repository.
cat >"$W/bao.py" <<P
import http.server, json, urllib.request
made = set()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_POST(s):
        body = json.loads(s.rfile.read(int(s.headers['content-length'])))
        if s.path == '/v1/auth/kubernetes/login':
            ok = body.get('role') == 'hsm-bootstrap' and body.get('jwt') == 'test-sa-jwt'
            s.send_response(200 if ok else 403); s.end_headers()
            if ok: s.wfile.write(b'{"auth":{"client_token":"t1"}}')
            return
        path = s.path[len('/v1/kbs/'):]
        if s.headers.get('X-Vault-Token') != 't1' or path in made: s.send_response(403); s.end_headers(); return
        req = urllib.request.Request('http://127.0.0.1:8080/kbs/v0/resource/' + path, data=body['data'].encode(),
                                     headers={'Authorization': 'Bearer $T'})
        urllib.request.urlopen(req); made.add(path); s.send_response(204); s.end_headers()
http.server.HTTPServer(('127.0.0.1', 18200), H).serve_forever()
P
python3 "$W/bao.py" & pids+=($!)
echo test-sa-jwt >"$W/jwt"
start() {  # svn -> runs the module, prints its log path
  local log="$W/hsm-$RANDOM.log"
  env -i PATH="$PATH" HOME="$HOME" HSM_KBS_URL=http://127.0.0.1:8080 HSM_TEE_SVN="$1" HSM_TMPFS="$W/run" HSM_ADDR=127.0.0.1:18701 \
    HSM_BOOTSTRAP_OPENBAO=http://127.0.0.1:18200 HSM_BOOTSTRAP_JWT="$W/jwt" \
    HSM_BOOTSTRAP_KEYS="cvk=CVK;dcvv2=CVK;zpk=ZPK;pvk=PVK;imk-ac=MK-AC;aes-pin=AES/P0;acs-hmac=AES/M7;acs-sign=RSA" \
    java -cp "$CP" dev.difme.hsm.HsmServer >"$log" 2>&1 & echo "$!:$log"
}
curl -sf localhost:18701/healthz >/dev/null 2>&1 && { echo "port 18701 already in use"; exit 1; }
stop() { kill "$1" 2>/dev/null || true; for i in $(seq 30); do curl -sf localhost:18701/healthz >/dev/null 2>&1 || return 0; sleep 1; done; }
up() { for i in $(seq 40); do curl -sf localhost:18701/healthz >/dev/null && return 0; sleep 1; done; return 1; }
fail() { echo "FAIL: $*"; cat "$W"/hsm-*.log | grep -v "Picked up" | tail -20; exit 1; }
IFS=: read -r pid log <<<"$(start 1)"; pids+=("$pid"); up || fail "first start"
grep -q "first start: generated in the module" "$log" || fail "no bootstrap"
cert1=$(curl -sf localhost:18701/v1/certs/acs-sign); code=$(curl -sf -X POST -d '{"pan":"4375510000000001"}' localhost:18701/v1/dcvv2 | sed 's/.*"code":"\([0-9]*\)".*/\1/')
sig=$(curl -sf -X POST -d '{"data":"00112233"}' localhost:18701/v1/sign/ps256 | sed 's/.*"signature":"\([0-9A-F]*\)".*/\1/')
[ ${#sig} -eq 512 ] || fail "PS256 signature"; echo "ok: first start, keys generated inside the module (dCVV2 $code, PS256 signature)"
ls "$W/run" | grep -q . && fail "key material left in the memory-backed directory"
stop "$pid"
IFS=: read -r pid log <<<"$(start 1)"; pids+=("$pid"); up || fail "restart"
grep -q "keys released by attestation$" "$log" || { grep -v "Picked up" "$log" | head -5; fail "restart did not use released keys"; }
[ "$(curl -sf localhost:18701/v1/certs/acs-sign)" = "$cert1" ] || fail "different signing key after restart"
curl -sf -X POST -d "{\"pan\":\"4375510000000001\",\"code\":\"$code\"}" localhost:18701/v1/dcvv2/verify | grep -q '"valid":"true"' || fail "dCVV2 key changed"
echo "ok: restart, the same keys released by attestation"
stop "$pid"
IFS=: read -r pid log <<<"$(start 2)"; pids+=("$pid"); sleep 8
if kill -0 "$pid" 2>/dev/null && curl -sf localhost:18701/healthz >/dev/null; then fail "started with a changed measurement"; fi
grep -q "PolicyDeny\|403" "$log" || fail "no refusal logged"; echo "ok: changed measurement, refused (no keys, not started)"
kill "$pid" 2>/dev/null || true
if env -i PATH="$PATH" java -cp "$CP" dev.difme.hsm.HsmServer >/dev/null 2>&1; then fail "started without attested key release"; fi
echo "ok: no KBS configured, refused to start"
echo "hsm key release PASS"

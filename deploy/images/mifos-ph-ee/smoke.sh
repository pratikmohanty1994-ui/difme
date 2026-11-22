#!/usr/bin/env bash
# Smoke test for a PH-EE connector image: it must start (Spring context, Camel routes, Fluxnova client) without
# Fluxnova or Fineract around, report itself live, and serve Prometheus metrics (VictoriaMetrics scrapes them).
# Usage: smoke.sh <image> <ams|channel|mojaloop>
set -euo pipefail
img=$1 c=$2
case "$c" in
  ams)      port=7070; base=/fineract ;;
  channel)  port=8443; base= ;;      # upstream's server port (DIFME's profile moves it to 8080 + management 8081)
  mojaloop) port=8080; base= ;;
  *) echo "unknown connector $c"; exit 1 ;;
esac
name=phee-smoke-$c
docker rm -f "$name" >/dev/null 2>&1 || true
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -p "127.0.0.1:18089:$port" \
  -e MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,prometheus \
  -e ZEEBE_BROKER_CONTACTPOINT=http://127.0.0.1:9/engine-rest "$img" >/dev/null
url="http://127.0.0.1:18089$base/actuator"
for i in $(seq 90); do
  curl -fs "$url/health/liveness" >/dev/null 2>&1 && break
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || { docker logs "$name" | tail -50; echo "✗ $c exited"; exit 1; }
  sleep 2
done
curl -fsS "$url/health/liveness" | grep -q '"UP"' || { docker logs "$name" | tail -80; echo "✗ $c not live"; exit 1; }
curl -fsS "$url/prometheus" | grep -q '^jvm_memory_used_bytes' || { docker logs "$name" | tail -40; echo "✗ $c: no Prometheus metrics"; exit 1; }
echo "✓ $c: live, Prometheus metrics served"

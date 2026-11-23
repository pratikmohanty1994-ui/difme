#!/usr/bin/env bash
# Wave-gated profile rollout (ADR-012). Enabling a whole profile at once while other apps were still syncing drove a
# 4-core node to load average 38 and made SSH time out (found live). This script:
#   1. waits until everything already deployed is Synced+Healthy;
#   2. applies the profile's apps in sync-wave order, one wave at a time, waiting for each wave to become healthy
#      (operators/CRDs before the things that use them; bounded concurrent work for the node).
# Usage: ci/up.sh <profile> [per-wave-timeout-seconds]
set -uo pipefail
cd "$(dirname "$0")/.."
PROFILE=${1:-core}
WAVE_TIMEOUT=${2:-600}

healthy() { # all given apps (or all apps when none given) are Synced+Healthy
  local out; out=$(kubectl -n argocd get applications "$@" --no-headers 2>/dev/null) || return 1
  [ -n "$out" ] && ! echo "$out" | grep -vqE 'Synced +Healthy'
}
wait_for() { # wait_for <timeout> [apps...]
  local deadline=$(( $(date +%s) + $1 )); shift
  until healthy "$@"; do
    [ "$(date +%s)" -ge "$deadline" ] && { echo "  ⚠ not healthy after timeout:"; kubectl -n argocd get applications "$@" --no-headers | grep -vE 'Synced +Healthy' | sed 's/^/    /'; return 1; }
    sleep 10
  done
}

if kubectl -n argocd get applications --no-headers 2>/dev/null | grep -q .; then
  echo "▶ waiting for already-deployed apps to settle"
  wait_for "$WAVE_TIMEOUT" || echo "  continuing anyway"
fi

# Codespace-only request scaling (deploy/bootstrap/dev-sizing.yaml). Needs Kyverno's CRDs, which the base profile
# installs, so it is applied here rather than in `make cluster`. Idempotent.
# DIFME_DEV_MEMORY_SCALING=1 (cluster-verify on GitHub runners) also halves memory requests: those hosts don't run
# earlyoom, which is why Codespaces keep memory requests as declared. Limits never change.
if kubectl get crd clusterpolicies.kyverno.io >/dev/null 2>&1; then
  if [ "${DIFME_DEV_MEMORY_SCALING:-0}" = 1 ]; then
    python3 ci/dev-sizing-memory.py deploy/bootstrap/dev-sizing.yaml | kubectl apply -f - >/dev/null && echo "▶ dev request scaling active (cpu/4, memory/2)"
  else
    kubectl apply -f deploy/bootstrap/dev-sizing.yaml >/dev/null && echo "▶ dev request scaling active"
  fi
fi

# Apps of this profile grouped by sync wave (ascending).
waves=$(python3 - "$PROFILE" <<'PY'
import sys, yaml
profile = sys.argv[1]
apps = [l.strip() for l in open(f"deploy/profiles/{profile}.txt") if l.strip() and not l.startswith("#")]
catalog = {c["name"]: c for c in yaml.safe_load(open("deploy/argocd/catalog.yaml"))["components"]}
by_wave = {}
for a in apps:
    by_wave.setdefault(int(catalog[a]["wave"]), []).append(a)
for w in sorted(by_wave):
    print(w, " ".join(by_wave[w]))
PY
)

start=$(date +%s)
while read -r wave apps; do
  [ -z "$wave" ] && continue
  echo "▶ wave $wave: $apps"
  # fail fast: a rejected Application (e.g. an invalid label, as Keycloak in run 3) never becomes healthy
  for a in $apps; do kubectl apply -f "deploy/argocd/apps/$a.yaml" >/dev/null || { echo "FAILFAST: Application $a rejected by the API server"; exit 3; }; done
  wait_for "$WAVE_TIMEOUT" $apps && echo "  ✓ wave $wave healthy"
done <<< "$waves"
echo "profile $PROFILE done in $(( $(date +%s) - start ))s"

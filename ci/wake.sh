#!/usr/bin/env bash
# Wake a scaled-to-zero tool for interactive use (ADR-029), wait until it serves, and keep it up until --sleep.
#   ci/wake.sh superset|trino|mlflow           pin 1 replica (KEDA paused-replicas), wait until ready, print the time
#   ci/wake.sh superset|trino|mlflow --sleep   hand the replica count back to KEDA (it scales down after the cooldown)
# Waking Superset also wakes Trino and the Celery worker (their triggers follow Superset's web pods).
set -euo pipefail
app=${1:?usage: ci/wake.sh superset|trino|mlflow [--sleep]}
case "$app" in
  superset) ns=lakehouse   so=superset deploy=superset ;;
  trino)    ns=lakehouse   so=trino    deploy=trino-coordinator ;;
  mlflow)   ns=ml-platform so=mlflow   deploy=mlflow ;;
  *) echo "unknown app $app (superset, trino, mlflow)"; exit 2 ;;
esac
if [ "${2:-}" = "--sleep" ]; then
  kubectl -n "$ns" annotate scaledobject "$so" autoscaling.keda.sh/paused-replicas- >/dev/null
  echo "$app: back under KEDA (scales to zero after its cooldown when idle)"
  exit 0
fi
t0=$(date +%s)
kubectl -n "$ns" annotate scaledobject "$so" autoscaling.keda.sh/paused-replicas=1 --overwrite >/dev/null
# KEDA applies the pinned count within a polling interval; then wait for the rollout.
for _ in $(seq 1 30); do
  [ "$(kubectl -n "$ns" get deploy "$deploy" -o jsonpath='{.spec.replicas}')" = "1" ] && break
  sleep 2
done
kubectl -n "$ns" rollout status "deploy/$deploy" --timeout=300s >/dev/null
echo "$app: ready after $(( $(date +%s) - t0 ))s (pinned up; 'ci/wake.sh $app --sleep' when done)"

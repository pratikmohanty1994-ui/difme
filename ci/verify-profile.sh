#!/usr/bin/env bash
# Install one profile on the running cluster and judge it: converged, sync failure or timeout. Prints the memory
# footprint before/after. Exit 0 only when every Argo CD app is Synced+Healthy.
#   ci/verify-profile.sh <profile> [deadline-seconds]
set -uo pipefail
cd "$(dirname "$0")/.."
P=${1:?profile}; DEADLINE=${2:-1800}
echo "== $P: before"; bash ci/mem-report.sh 3 | head -4
t=$(date +%s); make up PROFILE="$P" > "/tmp/up-$P.log" 2>&1; up_rc=$?; echo "UP_EXIT $up_rc $(( $(date +%s)-t ))s"
# A rejected Application is absent, not unhealthy, so the app check below would not see it (run 3: no Keycloak, yet
# "security: converged"). Fail fast instead.
if grep -q "FAILFAST: Application" "/tmp/up-$P.log"; then grep "FAILFAST: Application" "/tmp/up-$P.log"; echo "FAILFAST $P: Application rejected"; exit 1; fi
grep -E "⚠|error" "/tmp/up-$P.log" | head -5
apps() { kubectl -n argocd get applications -o jsonpath='{range .items[*]}{.metadata.name} {.status.operationState.phase} {.status.sync.status} {.status.health.status}{"\n"}{end}'; }
end=$(( $(date +%s) + DEADLINE )); firstfail=0; rc=1
# Fail fast (owner request 2026-11-20): a pod that is clearly broken ends the wait instead of the full deadline.
# Crash loop: >= 5 restarts and still crash-looping 3 min after first seen. Image/config errors: unchanged for 4 min.
# Startup crashes that recover (a service waiting for its database) stay below these bounds.
declare -A broken_since
broken_pods() {
  kubectl get pods -A --no-headers 2>/dev/null | awk '
    $4 == "CrashLoopBackOff" && $5+0 >= 5 { print $1"/"$2" crashloop 180"; next }
    $4 ~ /^(ImagePullBackOff|ErrImagePull|InvalidImageName|CreateContainerConfigError)$/ { print $1"/"$2" "$4" 240" }'
}
while :; do
  bad=$(apps | grep -vE "Succeeded Synced Healthy|^fleet-bundles|Synced Healthy$")
  [ -z "$bad" ] && { echo "CONVERGED $P $(( $(date +%s)-t ))s"; rc=0; break; }
  if echo "$bad" | grep -qE " (Failed|Error) "; then
    [ $firstfail -eq 0 ] && firstfail=$(date +%s)
    if [ $(( $(date +%s)-firstfail )) -gt 180 ]; then
      echo "SYNC FAILURE $P"; echo "$bad"
      kubectl -n argocd get applications -o jsonpath='{range .items[?(@.status.operationState.phase=="Failed")]}{.metadata.name}: {.status.operationState.message}{"\n"}{end}' | cut -c1-400
      break
    fi
  else firstfail=0; fi
  failfast=""; now=$(date +%s); declare -A seen=()
  while read -r pod why limit; do
    [ -n "$pod" ] || continue
    seen[$pod]=1; : "${broken_since[$pod]:=$now}"
    [ $(( now - broken_since[$pod] )) -ge "$limit" ] && failfast="$failfast $pod($why)"
  done < <(broken_pods)
  for k in "${!broken_since[@]}"; do [ -n "${seen[$k]:-}" ] || unset "broken_since[$k]"; done   # recovered pods reset
  [ -n "$failfast" ] && { echo "FAILFAST $P after $(( now - t ))s:$failfast"; echo "$bad"; break; }
  [ "$(date +%s)" -gt "$end" ] && { echo "TIMEOUT $P"; echo "$bad"; break; }
  sleep 20
done
if [ $rc -ne 0 ]; then
  echo "== pods not ready"; kubectl get pods -A --no-headers | grep -vE "Running|Completed" | cut -c1-120 | head -25
  # Crash-looping pods, plus pods that run but never turn ready (e.g. a new revision failing its probe).
  for p in $(kubectl get pods -A --no-headers | awk '$4 ~ /CrashLoop|Error|Pending/ || ($4 == "Running" && $3 ~ /^0\//) {print $1"/"$2}' | head -8); do
    echo "--- logs $p"; kubectl -n "${p%%/*}" logs "${p#*/}" --all-containers --tail=40 2>&1 | cut -c1-300
    kubectl -n "${p%%/*}" logs "${p#*/}" --all-containers --previous --tail=15 2>/dev/null | sed 's/^/  (previous) /' | cut -c1-300
    # Errors of the previous run: a long config dump (Trino's Bootstrap table) pushes them out of the tail.
    kubectl -n "${p%%/*}" logs "${p#*/}" --all-containers --previous 2>/dev/null | grep -E 'ERROR|FATAL|Exception:|Caused by|panic' | grep -v '^\s*at ' | head -8 | sed 's/^/  (previous error) /' | cut -c1-300
    kubectl -n "${p%%/*}" describe pod "${p#*/}" 2>/dev/null | sed -n '/^Events:/,$p' | tail -8
    # Startup lines: setup steps log once at start and scroll out of --tail (formio's db setup, 2026-11-20).
    echo "  (startup)"; kubectl -n "${p%%/*}" logs "${p#*/}" --all-containers 2>/dev/null | grep -vE '^    at |Update found|[█▄▀]' | head -70 | cut -c1-300
    # The body of a failing HTTP readiness probe often names the cause (formio's /health 400, 2026-11-20).
    probe=$(kubectl -n "${p%%/*}" get pod "${p#*/}" -o jsonpath='{.spec.containers[0].readinessProbe.httpGet.port} {.spec.containers[0].readinessProbe.httpGet.path}' 2>/dev/null)
    if [ -n "${probe% *}" ] && [ "${probe#* }" != "$probe" ]; then
      echo "  readiness body (${probe#* }):"; kubectl get --raw "/api/v1/namespaces/${p%%/*}/pods/${p#*/}:${probe% *}/proxy${probe#* }" 2>&1 | head -c 600; echo
    fi
  done
  # Apps can stay Progressing while every pod is Ready (a FlinkDeployment whose job keeps failing, a Rollout, a Job).
  # Print the resources Argo CD itself marks unhealthy, with their status and events (found 2026-11-20: flink-jobs).
  # Sync status Unknown/OutOfSync for a long time: Argo CD could not compare or generate the manifests (repo server
  # error, Helm/Kustomize failure, timeout); the reason is only in the app's conditions (run 8, 2026-11-23:
  # core-services stayed "Unknown" for 30 minutes with no failing pod).
  echo "== apps not Synced: Argo CD conditions"
  for a in $(kubectl -n argocd get applications -o jsonpath='{range .items[*]}{.metadata.name} {.status.sync.status}{"\n"}{end}' \
             | awk '$2 != "Synced" {print $1}' | grep -v '^fleet-bundles'); do
    kubectl -n argocd get application "$a" -o jsonpath='{range .status.conditions[*]}{.type}: {.message}{"\n"}{end}' 2>/dev/null \
      | sed "s|^|--- $a: |" | cut -c1-600
  done
  echo "== unhealthy resources (Argo CD view)"
  for a in $(apps | awk '$4 != "Healthy" {print $1}' | grep -v '^fleet-bundles'); do
    kubectl -n argocd get application "$a" -o jsonpath='{range .status.resources[?(@.health.status)]}{.kind} {.namespace} {.name} {.health.status} {.health.message}{"\n"}{end}' \
      | awk '$4 != "Healthy"' | head -6 | while read -r kind ns name hs msg; do
        echo "--- $a: $kind $ns/$name $hs ${msg:-}" | cut -c1-300
        kubectl -n "$ns" get "$kind" "$name" -o jsonpath='{.status}' 2>/dev/null | cut -c1-900; echo
        kubectl -n "$ns" get events --field-selector "involvedObject.name=$name" --sort-by=.lastTimestamp 2>/dev/null | tail -5 | cut -c1-250
        if [ "$kind" = DaemonSet ]; then           # node agents (istio-cni, ztunnel): their own log says why they aren't ready
          kubectl -n "$ns" logs "ds/$name" --all-containers --tail=60 2>&1 | grep -viE 'ip6?tables|^-A |^-N |^\*|COMMIT' | tail -25 | cut -c1-300
        fi
        if [ "$kind" = FlinkDeployment ]; then
          kubectl -n "$ns" logs "deploy/$name" --tail=40 2>&1 | grep -iE 'exception|error|caused by|failed' | tail -15 | cut -c1-300
        fi
      done
  done
  if kubectl -n istio-system get ds istio-cni-node >/dev/null 2>&1; then   # where do CNI configs live on this k3d node?
    for d in /etc/cni/net.d /var/lib/rancher/k3s/agent/etc/cni/net.d; do
      echo "--- node $d: $(docker exec k3d-difme-server-0 ls -la "$d" 2>&1 | tail -n +2 | awk '{print $NF}' | tr '\n' ' ')"
    done
  fi
  # Synced+Healthy is required; name what drifts (istio-base/istiod, 2026-11-20).
  echo "== out-of-sync resources (Argo CD view)"
  for a in $(apps | awk '$3 == "OutOfSync" {print $1}'); do
    kubectl -n argocd get application "$a" -o jsonpath='{range .status.resources[?(@.status=="OutOfSync")]}{.kind} {.namespace} {.name}{"\n"}{end}' \
      | head -8 | sed "s/^/  $a: /"
  done
  kubectl get rollouts -A 2>/dev/null | head; kubectl get rs -n core-platform 2>/dev/null | head -15
  echo "== recent warning events"; kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -20 | cut -c1-250
fi
echo "== $P: after"; bash ci/mem-report.sh 12
# Process/thread level (owner rule 2026-11-20): every process in every pod, its PSS, threads and thread groups.
# Idle measurements need the startup burst (jar and catalog loading) to pass first (2026-11-20 io pass).
if [ "${PROC_SETTLE:-0}" -gt 0 ] 2>/dev/null; then echo "== settling ${PROC_SETTLE}s before the process report"; sleep "$PROC_SETTLE"; fi
echo "== $P: processes"; sudo -n env "PATH=$PATH" "KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}" bash ci/proc-report.sh 45 2>/dev/null || bash ci/proc-report.sh 45
# YugabyteDB RPC mix (informational): which RPCs drive the idle tserver<->master traffic (2026-11-20: not heartbeats,
# not tablet count). Two samples of the *_count handler metrics 15 s apart; top methods by calls/s.
if kubectl -n database-tier get pod yb-master-0 >/dev/null 2>&1; then
  echo "== YugabyteDB RPC calls/s (top methods)"
  for t in "yb-master-0:7000" "yb-tserver-0:9000"; do
    u="/api/v1/namespaces/database-tier/pods/$t/proxy/prometheus-metrics"
    kubectl get --raw "$u" 2>/dev/null | grep -E '^handler_latency_.*_count' > /tmp/yb1.txt; sleep 15
    kubectl get --raw "$u" 2>/dev/null | grep -E '^handler_latency_.*_count' > /tmp/yb2.txt
    awk 'FNR==NR {a[$1]=$2; next} ($1 in a) {d=($2-a[$1])/15; if (d>0) printf "%.1f %s\n", d, $1}' /tmp/yb1.txt /tmp/yb2.txt \
      | sed -E 's/handler_latency_//; s/\{[^}]*\}//' | sort -nr | head -6 | sed "s|^|  ${t%%:*}: |"
  done
fi
# A/B for the catalog reads (2026-11-20: ~230 master Read/s from the streaming profile on): stop the Debezium
# connectors (YugabyteDB logical replication) for 45 s and sample the master's Read rate again, then resume them.
yb_reads() {
  u=/api/v1/namespaces/database-tier/pods/yb-master-0:7000/proxy/prometheus-metrics
  a=$(kubectl get --raw "$u" 2>/dev/null | awk '/^handler_latency_yb_tserver_TabletServerService_Read_count/ {s+=$2} END {print s+0}'); sleep 15
  b=$(kubectl get --raw "$u" 2>/dev/null | awk '/^handler_latency_yb_tserver_TabletServerService_Read_count/ {s+=$2} END {print s+0}')
  awk -v a="$a" -v b="$b" 'BEGIN {printf "%.1f", (b - a) / 15}'
}
if kubectl -n database-tier get pod yb-master-0 >/dev/null 2>&1 && kubectl -n streaming get kafkaconnector core-outbox >/dev/null 2>&1; then
  echo "== catalog reads A/B (Debezium connectors running vs stopped)"
  kubectl get --raw "/api/v1/namespaces/database-tier/pods/yb-tserver-0:9000/proxy/varz?raw=1" 2>/dev/null | grep -iE 'walsender|cdcsdk_.*(interval|poll)' | head -8 | sed 's/^/  flag: /'
  echo "  running: $(yb_reads) Read/s"
  conns=$(kubectl -n streaming get kafkaconnector -o name 2>/dev/null)
  for c in $conns; do kubectl -n streaming patch "$c" --type merge -p '{"spec":{"state":"stopped"}}' >/dev/null 2>&1; done
  sleep 45
  echo "  stopped: $(yb_reads) Read/s"
  for c in $conns; do kubectl -n streaming patch "$c" --type merge -p '{"spec":{"state":"running"}}' >/dev/null 2>&1; done
fi
# Evidence custody smoke: with the security switch present, the published keys must be the transit operator key and the
# notary's own key (local dev keys are named exchange-svc / exchange-witness).
if [ "$rc" -eq 0 ] && kubectl -n core-platform get configmap exchange-evidence >/dev/null 2>&1; then
  echo "== evidence signers"
  kubectl get --raw /api/v1/namespaces/core-platform/services/exchange-svc:8089/proxy/v1/exchange/keys 2>/dev/null \
    | python3 -c "import json,sys; k=json.load(sys.stdin); print('  published keys:', sorted(k)); print('  notary witness:', 'yes' if 'notary-1' in k else 'NO (local witness)')" 2>/dev/null \
    || echo "  (exchange-svc keys endpoint not reachable)"
  # During a rolling update the old pod keeps answering with local keys while a new one may be failing: show both.
  if ! kubectl get --raw /api/v1/namespaces/core-platform/services/exchange-svc:8089/proxy/v1/exchange/keys 2>/dev/null | grep -q notary; then
    kubectl -n core-platform get pods -l app=exchange-svc --no-headers 2>&1 | cut -c1-140
    newest=$(kubectl -n core-platform get pods -l app=exchange-svc --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | tail -1)
    [ -n "$newest" ] && kubectl -n core-platform logs "$newest" --tail=30 2>&1 | grep -iE 'evidence|openbao|notary|transit|error|exception|caused' | tail -12 | cut -c1-260
    echo "  restart job:"; kubectl -n core-platform logs job/exchange-evidence-restart --tail=5 2>&1 | cut -c1-200
    echo "  configmap: $(kubectl -n core-platform get configmap exchange-evidence -o jsonpath='{.data.DIFME_EVIDENCE_OPERATOR}' 2>&1)"
    kubectl -n argocd get application exchange-evidence -o jsonpath='  app: {.status.sync.status} {.status.health.status} {.status.operationState.phase} {.status.operationState.message}{"\n"}' 2>&1 | cut -c1-300
    kubectl -n core-platform get events --sort-by=.lastTimestamp 2>/dev/null | grep -iE 'exchange-evidence|exchange-svc' | tail -6 | cut -c1-220
  fi
fi
# Live buy smoke (informational): the full FR-01 path through the shopbot PWA's /api proxy.
if [ "$rc" -eq 0 ] && kubectl -n core-platform get svc pwa-shopbot >/dev/null 2>&1; then
  echo "== live buy through the PWA"
  python3 ci/live-buy.py || true
fi
# Rails checks (informational): settings that only show in healthy pods' logs, which the failing-pod report never sees.
if [ "$rc" -eq 0 ] && kubectl -n rails get deploy hyperswitch >/dev/null 2>&1; then
  echo "== rails: network tokenization, PH-EE flows, security module"
  kubectl -n rails logs deploy/hyperswitch -c nts-public-key --tail=3 2>&1 | sed 's/^/  hyperswitch init: /' | cut -c1-200
  kubectl -n rails logs deploy/hyperswitch -c router --tail=2000 2>/dev/null | grep -m1 "network tokenization on" | sed 's/^/  hyperswitch: /' \
    || echo "  hyperswitch: network tokenization NOT on"
  kubectl -n rails logs job/ph-ee-deploy-flows -c deploy --tail=2 2>&1 | sed 's/^/  ph-ee flows: /' | cut -c1-240
  kubectl -n rails logs deploy/hsm --tail=400 2>/dev/null | grep -iE "key release|attest|bootstrap|listening" | tail -4 | sed 's/^/  hsm: /' | cut -c1-200
fi
# Exchange restart smoke (informational): a mandate registered before the pod is replaced must still be there after
# (StateStore in YugabyteDB). Runs only where exchange-svc has its store configured.
if [ "$rc" -eq 0 ] && kubectl -n core-platform get deploy exchange-svc -o yaml 2>/dev/null | grep -q DIFME_EXCHANGE_STORE_URL; then
  echo "== exchange state survives a restart"
  ex=/api/v1/namespaces/core-platform/services/exchange-svc:8089/proxy/v1/exchange
  kubectl -n core-platform port-forward svc/exchange-svc 18089:8089 >/dev/null 2>&1 & pf=$!; sleep 3
  mid=$(curl -s -X POST -H 'Content-Type: application/json' localhost:18089/v1/exchange/fr01-buy/mandates -d '{"partnerRef":"restart-smoke","limitMinor":2500000,"maxPerOrderMinor":2500000,"minYieldPct":4,"depositMinor":2000000,"budgetTotalMinor":2500000,"merchantCount":2,"goodsCount":5,"validityDays":5,"cardJurisdiction":"IN_DOMESTIC_AFA"}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mandateId",""))' 2>/dev/null)
  kill $pf 2>/dev/null
  sleep 1   # > the 50 ms flush interval
  if [ -n "$mid" ]; then
    kubectl -n core-platform rollout restart deploy/exchange-svc >/dev/null && kubectl -n core-platform rollout status deploy/exchange-svc --timeout=180s >/dev/null 2>&1
    got=$(kubectl get --raw "$ex/fr01-buy/mandates/$mid" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mandateId",""))' 2>/dev/null)
    [ "$got" = "$mid" ] && echo "  mandate $mid survived the restart: ok" || echo "  mandate $mid NOT found after the restart"
    kubectl -n core-platform logs deploy/exchange-svc --tail=200 2>/dev/null | grep -E "state restored|state store|cannot load" | tail -2 | cut -c1-200
  else
    echo "  could not register a mandate"
  fi
fi
# Lineage smoke (informational): what has reached Marquez (Trino queries, dbt runs every 15 min, Flink job status).
if [ "$rc" -eq 0 ] && kubectl -n governance get svc marquez >/dev/null 2>&1; then
  echo "== lineage in Marquez"
  # Active smoke: run dbt now (it goes through dbt-ol and Trino, so both emitters fire) instead of waiting for the cron.
  if kubectl -n lakehouse get cronjob dbt-run >/dev/null 2>&1; then
    kubectl -n lakehouse delete job dbt-lineage-smoke --ignore-not-found >/dev/null 2>&1
    if ! out=$(kubectl -n lakehouse create job --from=cronjob/dbt-run dbt-lineage-smoke 2>&1); then
      echo "  dbt run: could not create the job: $out" | cut -c1-300
    elif kubectl -n lakehouse wait --for=condition=complete job/dbt-lineage-smoke --timeout=420s >/dev/null 2>&1; then
      echo "  dbt run: complete"
    else
      echo "  dbt run: not complete"
      kubectl -n lakehouse get pods -l job-name=dbt-lineage-smoke --no-headers 2>&1 | cut -c1-160
      kubectl -n lakehouse logs -l job-name=dbt-lineage-smoke --all-containers --tail=25 2>&1 | cut -c1-220
      kubectl -n lakehouse get events --field-selector involvedObject.kind=Pod --sort-by=.lastTimestamp 2>/dev/null | grep dbt-lineage | tail -5 | cut -c1-220
    fi
    sleep 10
  fi
  m=/api/v1/namespaces/governance/services/marquez:5000/proxy/api/v1
  kubectl get --raw "$m/namespaces" 2>/dev/null | python3 -c "import json,sys; print('  namespaces:', [n['name'] for n in json.load(sys.stdin).get('namespaces',[])])" 2>/dev/null || echo "  (Marquez API not reachable)"
  kubectl get --raw "$m/namespaces/difme/jobs?limit=20" 2>/dev/null | python3 -c "import json,sys; j=json.load(sys.stdin).get('jobs',[]); print('  difme jobs:', len(j), [x['name'][:60] for x in j[:8]])" 2>/dev/null || true
fi
exit $rc

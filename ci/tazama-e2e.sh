#!/usr/bin/env bash
# ADR-023 end-to-end check of Tazama on DIFME's stack, with Docker: Postgres 18 (Tazama's schema), Valkey and Kafka in
# containers, the six images built from deploy/images/tazama, the committed env files (deploy/platform/fraud/tazama/env)
# pointed at localhost. Sends one pacs.008 + pacs.002 to TMS and expects the adjudicator to store an evaluation with
# status ALRT for that EndToEndId (rules 901 + 902 at .01 each = 200, the typology's alert threshold).
# Extra docker build args (e.g. a proxy) in DOCKER_BUILD_ARGS; another Dockerfile (e.g. one adding a proxy CA) in
# TAZAMA_DOCKERFILE.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
work=$(mktemp -d); pw=tazama-e2e
svc=(tms:tms-service event-director:event-director rule-901:rule-901 rule-902:rule-902 rule-d01:rule-d01 typology-processor:typology-processor
     event-adjudicator:event-adjudicator)
cleanup() { docker rm -f tz-e2e-pg tz-e2e-valkey tz-e2e-kafka tz-e2e-scorer "${svc[@]/#/tz-e2e-}" >/dev/null 2>&1 || true; }
cleanup; trap cleanup EXIT
for s in "${svc[@]}"; do
  img=${s%%:*}; case $img in tms) b=tms-service r=rule-901;; rule-*) b=rule-executer r=$img;; *) b=$img r=rule-901;; esac
  # shellcheck disable=SC2086
  docker build -q ${DOCKER_BUILD_ARGS:-} -f "${TAZAMA_DOCKERFILE:-deploy/images/tazama/Dockerfile}" --build-arg SERVICE=$b --build-arg RULE=$r \
    -t difme-tazama-$img:e2e . >/dev/null
done
echo "images built"
sql=$work/sql; mkdir -p "$sql"
cp vendor/tazama/stack-postgres/base/{00-CREATE,01-tcs-init,02-trs-init}.sql vendor/tazama/stack-postgres/config/00-public-base.sql \
   deploy/platform/fraud/tazama/difme-network-map.sql deploy/platform/fraud/tazama/schema.sh "$sql/"
docker run -d --name tz-e2e-pg -p 5432:5432 -e POSTGRES_PASSWORD=$pw -v "$sql:/sql:ro" postgres:18 >/dev/null
docker run -d --name tz-e2e-valkey -p 6379:6379 valkey/valkey:8 >/dev/null
docker run -d --name tz-e2e-kafka -p 9092:9092 apache/kafka:4.1.1 >/dev/null
# Stand-in for DIFME's fraud scorer: probability 0.7 for every order (the model's BLOCK band), so rule D01 gives .03.
docker run -d --name tz-e2e-scorer --network host node:22-bookworm node -e "require('http').createServer((q, s) => {
  let b = ''; q.on('data', (c) => (b += c)); q.on('end', () => { s.writeHead(200, { 'content-type': 'application/json' });
  s.end(JSON.stringify({ probability: 0.7, riskScore: 300, decision: 'BLOCK', model: 'e2e-stub' })); }); }).listen(8090)" >/dev/null
until docker exec tz-e2e-pg pg_isready -q -U postgres 2>/dev/null; do sleep 2; done; sleep 3
for db in configuration event_history raw_history evaluation enrichment; do
  docker exec tz-e2e-pg psql -q -U postgres -c "create database tazama_$db"
done
# the same schema step the cluster's job runs
docker exec -e PGUSER=postgres tz-e2e-pg sh /sql/schema.sh /sql
until (echo >/dev/tcp/127.0.0.1/9092) 2>/dev/null; do sleep 1; done; sleep 5
for s in "${svc[@]}"; do
  img=${s%%:*} env=${s#*:}
  sed -E 's/postgres-docdb\.database-tier\.svc/localhost/; s/valkey\.cache-tier\.svc/localhost/;
          s/^SERVER_URL=.*/SERVER_URL=localhost:9092/; s/^APM_ACTIVE=.*/APM_ACTIVE=false/;
          s/^([A-Z_]*_DATABASE_PORT)=$/\1=5432/; s/^([A-Z_]*_DATABASE_USER)=tazama/\1=postgres/;
          s#^FRAUD_SCORER_URL=.*#FRAUD_SCORER_URL=http://localhost:8090#' \
    "deploy/platform/fraud/tazama/env/$env.env" | grep -v '^#' >"$work/$env.env"
  grep -o '^[A-Z_]*_DATABASE_HOST' "$work/$env.env" | sed "s/_HOST\$/_PASSWORD=$pw/" >>"$work/$env.env"
  grep -q '^AUTHENTICATED=' "$work/$env.env" || echo AUTHENTICATED=false >>"$work/$env.env"
  docker run -d --name "tz-e2e-$img" --network host --env-file "$work/$env.env" "difme-tazama-$img:e2e" >/dev/null
done
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/ || true)" != 000 ]; do sleep 2; done; sleep 10
e2e=$(node -e "
  const d = require('./vendor/tazama/frms-coe-lib/lib/tests/data'); const fs = require('fs'); const id = () => require('crypto').randomUUID().replace(/-/g, '');
  const e2e = id(), now = new Date().toISOString();
  const a = structuredClone(d.Pacs008Sample), b = structuredClone(d.Pacs002Sample); delete a.TenantId; delete b.TenantId;
  Object.assign(a.FIToFICstmrCdtTrf.GrpHdr, { MsgId: id(), CreDtTm: now }); a.FIToFICstmrCdtTrf.CdtTrfTxInf.PmtId.EndToEndId = e2e;
  Object.assign(b.FIToFIPmtSts.GrpHdr, { MsgId: id(), CreDtTm: now }); b.FIToFIPmtSts.TxInfAndSts.OrgnlEndToEndId = e2e;
  fs.writeFileSync('$work/008.json', JSON.stringify(a)); fs.writeFileSync('$work/002.json', JSON.stringify(b)); console.log(e2e);")
for m in pacs.008.001.10:008 pacs.002.001.12:002; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data "@$work/${m#*:}.json" "http://127.0.0.1:3000/v1/evaluate/iso20022/${m%%:*}")
  [ "$code" = 200 ] || { echo "FAIL: TMS answered $code to ${m%%:*}"; exit 1; }
  sleep 2
done
for _ in $(seq 1 30); do
  st=$(docker exec tz-e2e-pg psql -U postgres -d tazama_evaluation -tAc \
    "select evaluation->'report'->>'status' from evaluation where evaluation::text like '%$e2e%' limit 1")
  [ -n "$st" ] && break; sleep 2
done
echo "EndToEndId $e2e -> ${st:-no evaluation}"
[ "$st" = ALRT ] || { echo FAIL; exit 1; }
# Typology scores: public rules 901 + 902 = 200 (alert); DIFME's D01 at the model's BLOCK band = 400 (interdiction).
scores=$(docker exec tz-e2e-pg psql -U postgres -d tazama_evaluation -tAc "select string_agg(t->>'cfg' || '=' || (t->>'result'), ' ' order by t->>'cfg')
  from evaluation, jsonb_array_elements(evaluation->'report'->'tadpResult'->'typologyResult') t where evaluation::text like '%$e2e%'")
echo "typology scores: $scores"
[ "$scores" = "difme-901-902@1.0.0=200 difme-fraud-model@1.0.0=400" ] && echo PASS || { echo FAIL; exit 1; }

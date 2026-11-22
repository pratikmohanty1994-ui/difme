#!/usr/bin/env bash
# Creates every Secret the manifests reference, with random values, for a Codespace/dev cluster.
# Idempotent: existing secrets are never overwritten. Production clusters get these from OpenBao instead.
set -euo pipefail

rand() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${1:-24}"; }
ns() { kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; }
secret() {  # secret <namespace> <name> key=value...
  local n=$1 name=$2; shift 2; ns "$n"
  if kubectl -n "$n" get secret "$name" >/dev/null 2>&1; then echo "= $n/$name exists"; return; fi
  local args=(); for kv in "$@"; do args+=(--from-literal="$kv"); done
  kubectl -n "$n" create secret generic "$name" "${args[@]}" >/dev/null && echo "+ $n/$name"
}

# Shared credentials, generated once and replicated where several namespaces need them.
PG_DOCDB=$(rand); FLUX_ADMIN=$(rand); FORMIO_KEY=$(rand 32); S3_KEY=$(rand 20); S3_SECRET=$(rand 40); YB=$(rand)

secret database-tier postgres-docdb password="$PG_DOCDB"
secret process       postgres-docdb password="$PG_DOCDB"
secret forms         ferretdb postgresql-url="postgres://difme:${PG_DOCDB}@postgres-docdb.database-tier.svc:5432/postgres"
# FerretDB 2 requires authentication and checks the credentials against PostgreSQL (SCRAM-SHA-256 only), so formio
# connects as the shared Postgres role (cluster-verify 2026-11-20: "listCollections requires authentication").
secret forms         formio api-key="$FORMIO_KEY" api-keys="$FORMIO_KEY" jwt-secret="$(rand 48)" \
                     mongo-url="mongodb://difme:${PG_DOCDB}@ferretdb.forms.svc:27017/formio?authMechanism=SCRAM-SHA-256" root-email="admin@difme.local" root-password="$(rand)"
secret process       formio api-key="$FORMIO_KEY"
secret process       fluxnova admin-password="$FLUX_ADMIN" admin-basic="admin:${FLUX_ADMIN}"

cat > /tmp/s3.json <<EOF
{"identities":[{"name":"difme","credentials":[{"accessKey":"${S3_KEY}","secretKey":"${S3_SECRET}"}],"actions":["Admin","Read","Write","List","Tagging"]}]}
EOF
ns lakehouse
kubectl -n lakehouse get secret seaweedfs-s3-config >/dev/null 2>&1 || kubectl -n lakehouse create secret generic seaweedfs-s3-config --from-file=s3.json=/tmp/s3.json >/dev/null
rm -f /tmp/s3.json
secret lakehouse     seaweedfs-s3-admin RCLONE_CONFIG_SW_TYPE=s3 RCLONE_CONFIG_SW_PROVIDER=SeaweedFS \
                     RCLONE_CONFIG_SW_ENDPOINT=http://seaweedfs-s3:8333 RCLONE_CONFIG_SW_ACCESS_KEY_ID="$S3_KEY" RCLONE_CONFIG_SW_SECRET_ACCESS_KEY="$S3_SECRET"
POLARIS_SECRET=$(rand)   # one secret for the bootstrap principal and the clients (they were generated separately and could never match)
secret lakehouse     polaris-bootstrap credentials="POLARIS,root,$POLARIS_SECRET"
POLARIS_PG=$(rand)
secret lakehouse     polaris-db password="$POLARIS_PG"
secret database-tier polaris-db password="$POLARIS_PG"
FINERACT_PG=$(rand)
ns rails
secret rails         fineract-db password="$FINERACT_PG" master-password="$(rand)"   # logins go through Keycloak (no Fineract admin password)
secret database-tier fineract-db password="$FINERACT_PG"
secret rails         fineract-s3 access-key="$S3_KEY" secret-key="$S3_SECRET"   # documents on SeaweedFS (component reuse)
# Keycloak confidential clients: the same secret in Keycloak's namespace and in each client's namespace.
PHEE_AMS_CS=$(rand 32); EXCHANGE_CS=$(rand 32); FIN_ADMIN_CS=$(rand 32)
secret security      keycloak-clients ph-ee-ams="$PHEE_AMS_CS" difme-exchange="$EXCHANGE_CS" fineract-admin="$FIN_ADMIN_CS"
secret rails         ph-ee-ams-oauth client-id=ph-ee-ams client-secret="$PHEE_AMS_CS"
secret rails         fineract-admin-oauth client-id=fineract-admin client-secret="$FIN_ADMIN_CS"
secret core-platform difme-exchange-oauth client-id=difme-exchange client-secret="$EXCHANGE_CS"
HYPERSWITCH_PG=$(rand)
hex32() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }   # Hyperswitch wants 32-byte hex keys
secret rails         hyperswitch db-password="$HYPERSWITCH_PG" admin-api-key="$(rand 32)" jwt-secret="$(rand 48)" \
                     master-enc-key="$(hex32)" api-key-hash-key="$(hex32)" acquirer-api-key="$(rand 32)"
secret database-tier hyperswitch-db password="$HYPERSWITCH_PG"
# Card security (ADR-026/027): no keys here. The security module gets them only through attested key release.
TAZAMA_PG=$(rand)
secret fraud         tazama-db password="$TAZAMA_PG"
secret database-tier tazama-db password="$TAZAMA_PG"
APICURIO_PG=$(rand)
secret streaming     apicurio-db password="$APICURIO_PG"
secret database-tier apicurio-db password="$APICURIO_PG"
secret lakehouse     superset-secret-key key="$(rand 48)"
secret streaming     risingwave-s3 AWS_ACCESS_KEY_ID="$S3_KEY" AWS_SECRET_ACCESS_KEY="$S3_SECRET"   # key names the chart requires
# RisingWave meta store is on the shared Postgres (ADR-019 pattern); both copies must match, so reuse an existing one.
RW_PG=$(kubectl -n streaming get secret risingwave-db -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true); RW_PG=${RW_PG:-$(rand)}
secret streaming     risingwave-db username=risingwave password="$RW_PG"
secret database-tier risingwave-db password="$RW_PG"
secret streaming     debezium-db password="$YB"
secret ml-platform   mlflow-s3 AWS_ACCESS_KEY_ID="$S3_KEY" AWS_SECRET_ACCESS_KEY="$S3_SECRET"
MLFLOW_PG=$(rand)
secret ml-platform   mlflow-db username=mlflow password="$MLFLOW_PG"
secret database-tier mlflow-db username=mlflow password="$MLFLOW_PG"
secret ml-platform   postgresml-db password="$(rand)"
secret backup        velero-s3 cloud="$(printf '[default]\naws_access_key_id=%s\naws_secret_access_key=%s\n' "$S3_KEY" "$S3_SECRET")"
# Temporal persists on the shared platform Postgres (ADR-019). Reuse an existing password so both copies match.
TEMPORAL_PG=$(kubectl -n temporal get secret temporal-db -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)
TEMPORAL_PG=${TEMPORAL_PG:-$(rand)}
secret temporal      temporal-db password="$TEMPORAL_PG"
secret database-tier temporal-db password="$TEMPORAL_PG"
# Harbor's database is on the shared Postgres (ADR-019); both copies must match, so reuse an existing one.
HARBOR_PG=$(kubectl -n harbor get secret harbor-db -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true); HARBOR_PG=${HARBOR_PG:-$(rand)}
secret harbor        harbor-db password="$HARBOR_PG"
secret database-tier harbor-db password="$HARBOR_PG"
MARQUEZ_PG=$(rand)
secret database-tier marquez-db password="$MARQUEZ_PG"
secret governance    marquez-db password="$MARQUEZ_PG"
ML_PG=$(rand)
secret database-tier ml-db password="$ML_PG"
secret ml-platform   ml-db password="$ML_PG"
# Harbor's own secrets, fixed once per cluster: the chart would otherwise re-randomise them on every Argo CD render
# (its lookup() sees nothing), rolling harbor-core mid-migration (cluster-verify 2026-11-20). See harbor/values.yaml.
secret harbor        harbor-dev-secretkey secretKey="$(rand 16)"
secret harbor        harbor-dev-admin HARBOR_ADMIN_PASSWORD="$(rand)"
secret harbor        harbor-dev-core secret="$(rand 16)" CSRF_KEY="$(rand 32)"
secret harbor        harbor-dev-jobservice JOBSERVICE_SECRET="$(rand 16)"
secret harbor        harbor-dev-registry REGISTRY_HTTP_SECRET="$(rand 16)"
if ! kubectl -n harbor get secret harbor-dev-registry-credentials >/dev/null 2>&1; then
  # The registry reads a bcrypt htpasswd line; Python's bcrypt (Apache-2.0) makes it. Prefix 2a for the Go parser.
  python3 -c 'import bcrypt' 2>/dev/null || pip install -q --user --break-system-packages bcrypt==4.2.1 2>/dev/null || pip install -q --user bcrypt==4.2.1
  REG_PW=$(rand)
  REG_HT=$(python3 -c 'import bcrypt,sys; print("harbor_registry_user:" + bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(10, b"2a")).decode())' "$REG_PW")
  secret harbor      harbor-dev-registry-credentials REGISTRY_PASSWD="$REG_PW" REGISTRY_HTPASSWD="$REG_HT"
fi
if ! kubectl -n harbor get secret harbor-dev-token >/dev/null 2>&1; then
  t=$(mktemp -d)
  openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -subj "/CN=harbor-token-ca" -keyout "$t/tls.key" -out "$t/tls.crt" 2>/dev/null
  kubectl -n harbor create secret tls harbor-dev-token --cert="$t/tls.crt" --key="$t/tls.key" >/dev/null && echo "+ harbor/harbor-dev-token"
  rm -rf "$t"
fi
secret observability grafana-admin admin-user=admin admin-password="$(rand)"
secret security      keycloak admin-password="$(rand)"
# OpenBao static auto-unseal key (32 bytes, hex). Dev only; production uses a KMS/transit seal.
secret security      openbao-unseal key="$(head -c 32 /dev/urandom | xxd -p -c 64)"
secret security      warpgate admin-password="$(rand)"
# Veraison EAR signing key: EC P-256 as a JWK (Veraison's loader only reads JWK). b64u: hex -> base64url.
b64u() { xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '='; }
ear_jwk() {
  local t; t=$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -text -noout 2>/dev/null)
  local d pub; d=$(echo "$t" | awk '/priv:/{f=1;next} /pub:/{f=0} f' | tr -d ' :
')
  pub=$(echo "$t" | awk '/pub:/{f=1;next} /ASN1 OID/{f=0} f' | tr -d ' :
'); pub=${pub#04}
  printf '{"kty":"EC","crv":"P-256","alg":"ES256","d":"%s","x":"%s","y":"%s"}'     "$(printf %s "${d: -64}" | b64u)" "$(printf %s "${pub:0:64}" | b64u)" "$(printf %s "${pub:64:64}" | b64u)"
}
kubectl -n security get secret veraison-ear >/dev/null 2>&1 || secret security veraison-ear skey.jwk="$(ear_jwk)"
secret security      postgres-docdb password="$PG_DOCDB"
POLARIS_CRED="root:$POLARIS_SECRET"
for n in streaming lakehouse; do
  secret $n polaris-client credential="$POLARIS_CRED"
  secret $n flink-s3 access-key="$S3_KEY" secret-key="$S3_SECRET"
done
secret streaming     bulk-db password="$YB"
secret security      notary-key seed="$(head -c 32 /dev/urandom | base64)"   # the notary's own Ed25519 seed, never shared with the exchange
echo "Dev secrets ready. Read one with: kubectl -n <ns> get secret <name> -o jsonpath='{.data.<key>}' | base64 -d"

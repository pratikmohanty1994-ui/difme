#!/usr/bin/env bash
# ADR-026 hands-on check: the security module's master key (LMK) is released only to an attested TEE.
# OpenBao (dev server) holds the LMK; Trustee's key broker (KBS) reads it with a read-only token and releases it, as
# JWE encrypted to the TEE's own key, only when the attestation result is affirming. The TEE is Trustee's emulated
# "sample" TEE, whose svn stands in for the module's code measurement.
# Needs: docker compose, a Trustee checkout ($TRUSTEE_DIR), kbs-client built from it ($KBS_CLIENT), bao ($BAO).
# Expected: no reference value -> refused; measurement registered -> released (matches OpenBao); changed -> refused.
set -euo pipefail
: "${TRUSTEE_DIR:?Trustee checkout}" "${KBS_CLIENT:?kbs-client binary}" "${BAO:?bao binary}"
here=$(cd "$(dirname "$0")/.." && pwd); pol=$here/deploy/platform/security/tee-key-release
work=$(mktemp -d); export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root
"$BAO" server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 >"$work/bao.log" 2>&1 & bao_pid=$!
trap 'kill $bao_pid 2>/dev/null; (cd "$work" && docker compose down -v >/dev/null 2>&1)' EXIT
until curl -sf "$BAO_ADDR/v1/sys/health" >/dev/null; do sleep 1; done
"$BAO" secrets enable -path=kbs -version=1 kv >/dev/null
lmk=$(openssl rand -hex 16); "$BAO" write kbs/difme/hsm/lmk data="$lmk" >/dev/null
printf 'path "kbs/difme/*" { capabilities = ["read"] }\n' | "$BAO" policy write kbs-read - >/dev/null
token=$("$BAO" token create -policy=kbs-read -field=token)
cp "$TRUSTEE_DIR/docker-compose.yml" "$work/"; mkdir -p "$work/kbs/config" "$work/kbs/data"
cp -r "$TRUSTEE_DIR/kbs/config/docker-compose" "$work/kbs/config/"
cfg=$work/kbs/config/docker-compose/kbs-config.toml
sed -i '/^\[\[plugins\]\]/,$d' "$cfg"
cat >>"$cfg" <<T
[[plugins]]
name = "resource"
storage_backend_type = "Vault"
vault_url = "http://host.docker.internal:8200"
token = "$token"
mount_path = "kbs"

[storage_backend]
storage_type = "LocalFs"

[storage_backend.backends.local_fs]
dir_path = "/opt/confidential-containers/kbs"
T
printf 'services:\n  kbs:\n    extra_hosts: ["host.docker.internal:host-gateway"]\n' >"$work/docker-compose.override.yml"
cd "$work"; docker compose up -d --no-build >/dev/null 2>&1
until curl -s -o /dev/null http://127.0.0.1:8080/kbs/v0/auth 2>/dev/null; do sleep 1; done; sleep 3
c() { "$KBS_CLIENT" --url http://127.0.0.1:8080 "$@"; }
get() { RUST_BACKTRACE=0 c get-resource --path difme/hsm/lmk 2>/dev/null | tail -1 | base64 -d 2>/dev/null || true; }
c config set-attestation-policy --type rego --id default_cpu --policy-file "$pol/attestation-policy.dev.rego" >/dev/null
c config set-resource-policy --policy-file "$pol/resource-policy.rego" >/dev/null
[ -z "$(get)" ] && echo "ok: refused without a registered measurement" || { echo "FAIL: released without attestation"; exit 1; }
c config set-sample-reference-value difme_hsm_measurement 1 >/dev/null
[ "$(get)" = "$lmk" ] && echo "ok: released to the attested TEE (matches OpenBao)" || { echo "FAIL: not released"; exit 1; }
c config set-sample-reference-value difme_hsm_measurement 2 >/dev/null
[ -z "$(get)" ] && echo "ok: refused after the measurement changed" || { echo "FAIL: released to a changed build"; exit 1; }
echo PASS

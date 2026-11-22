#!/usr/bin/env bash
# F2, once per cluster whose OpenBao existed before the openbao-config initialize block: creates the openbao-config
# policy and Kubernetes role (taken from deploy/platform/security/openbao-config/requests.json, i.e. from values.yaml),
# after which the openbao-config Job keeps OpenBao's configuration current on every sync.
# Needs: kubectl to the cluster and an OpenBao token with admin rights in BAO_TOKEN (never stored anywhere).
set -euo pipefail
: "${BAO_TOKEN:?an OpenBao admin token (used once, not stored)}"
cd "$(dirname "$0")/.."
python3 - <<'P' | while IFS=$'\t' read -r path body; do
import json
for r in json.load(open("deploy/platform/security/openbao-config/requests.json")):
    if r["block"] == "openbao-config":
        print(r["path"], json.dumps(r["data"]), sep="\t")
P
  kubectl -n security exec -i openbao-0 -- env BAO_TOKEN="$BAO_TOKEN" sh -c \
    "wget -q -O- --header='X-Vault-Token: $BAO_TOKEN' --post-data='$body' http://127.0.0.1:8200/v1/$path >/dev/null && echo '+ $path'"
done
echo "openbao-config role in place: the openbao-config Job applies the rest at the next sync"

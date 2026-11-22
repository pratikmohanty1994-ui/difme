#!/usr/bin/env bash
# ADR-026 guard: keys reach the security module only through attested key release. Fails when the deployment tree
# carries key material or the module's insecure development switches, or when the module is not in attested mode.
set -euo pipefail
cd "$(dirname "$0")/.."
bad=0
if grep -rnE 'HSM_DEV_(KEYS|INSECURE|REBUILD_LMK|CVK_COMPONENTS)|HSM_CVK_UNDER_LMK|HSM_KEYS\b|ACS_PAYER_KEY|card-security-dev' deploy/; then
  echo "FAIL: security-module development key switches or key values in deploy/"; bad=1
fi
# long hex strings (16+ bytes) next to key-ish names in manifests and bootstrap scripts
if grep -rniE '(key|lmk|kbpk|cvk|zpk|pvk|imk)[a-z_-]*["'"'"' ]*[:=][ "'"'"']*[0-9a-f]{32,}' deploy/ --include=*.yaml --include=*.sh --include=*.toml | grep -viE 'sha256|digest|@sha'; then
  echo "FAIL: something that looks like a clear key in deploy/"; bad=1
fi
grep -q 'HSM_KBS_URL' deploy/platform/rails/card-security/card-security.yaml || { echo "FAIL: the security module is not in attested key release mode"; bad=1; }
[ $bad = 0 ] && echo "no key material in deploy/: ok"
exit $bad

#!/usr/bin/env bash
# Re-vendors upstream source at a pinned tag (ADR-008; owner 2026-11-21: copy outside projects into vendor/ and build
# from there). Usage: ci/vendor-sync.sh <target> <tag|commit>, e.g. ci/vendor-sync.sh hyperswitch v1.129.0
# (a 40-hex commit pins repos without release tags).
# A shallow git clone of the tag (no history), minus upstream CI, assistant files and non-build material, recorded in
# vendor/VENDORED.json. Local changes to vendored code are patch files in vendor/patches/<target>/ (re-applied here) and
# are listed in the target's VENDOR.md, never silent edits.
set -euo pipefail
what=$1 tag=$2
prune=() keep=""
case "$what" in
  formio-server) repo=formio/formio;      dest=vendor/formio/server ;;
  formio-js)     repo=formio/formio.js;   dest=vendor/formio/js ;;
  # PSP (PA/PG) simulator. Docs, Postman/Cypress suites and the API reference aren't part of the Cargo workspace.
  hyperswitch)   repo=juspay/hyperswitch; dest=vendor/hyperswitch; prune=(docs postman cypress-tests api-reference) ;;
  # Core banking (CBS). Kept whole: its test modules are wired into the Gradle build.
  fineract)      repo=apache/fineract;    dest=vendor/fineract ;;
  # ISO 8583 library for the scheme simulator and adapter (services/scheme-sim).
  moov-iso8583)  repo=moov-io/iso8583;    dest=vendor/moov-iso8583 ;;
  # Mifos Payment Hub EE (MPL-2.0; owner 2026-11-21: reuse it, with Fluxnova in place of Zeebe).
  ph-ee-common)    repo=openMF/ph-ee-connector-common;    dest=vendor/mifos-ph-ee/connector-common ;;
  ph-ee-channel)   repo=openMF/ph-ee-connector-channel;   dest=vendor/mifos-ph-ee/connector-channel ;;
  ph-ee-ams-mifos) repo=openMF/ph-ee-connector-ams-mifos; dest=vendor/mifos-ph-ee/connector-ams-mifos ;;
  # The BPMN flows only; the rest of env-labs is their own cluster's Helm/env config.
  ph-ee-flows)     repo=openMF/ph-ee-env-labs;            dest=vendor/mifos-ph-ee/flows; keep=orchestration/feel ;;
  ph-ee-mojaloop)  repo=openMF/ph-ee-connector-mojaloop-java; dest=vendor/mifos-ph-ee/connector-mojaloop ;;
  # Interledger codecs (Apache-2.0) at the 0.6.1 API PH-EE's Mojaloop connector was written against (no release tag:
  # pinned by commit). Replaces the jar bundled in interop-ilp-conditions, whose licence forbids use without permission.
  java-ilp-core)   repo=interledger/java-ilp-core;     dest=vendor/interledger/java-ilp-core ;;
  # Mojaloop (Apache-2.0; owner 2026-11-21): the Testing Toolkit plays the central switch, mojaloop-simulator the other bank.
  ml-ttk)          repo=mojaloop/ml-testing-toolkit;  dest=vendor/mojaloop/testing-toolkit ;;
  ml-simulator)    repo=mojaloop/mojaloop-simulator;  dest=vendor/mojaloop/simulator ;;
  # Speaks FSPIOP to the switch for the simulated bank (mojaloop-simulator is the bank's back end behind it).
  ml-sdk-adapter)  repo=mojaloop/sdk-scheme-adapter;  dest=vendor/mojaloop/sdk-scheme-adapter ;;
  # Tazama real-time fraud and AML monitoring (Apache-2.0; owner 2026-11-22: fraud scoring and FRM run on Tazama, with
  # DIFME's stack in place of its redundant infrastructure, ADR-023). Target tazama-<repo> -> vendor/tazama/<repo>.
  tazama-*)        repo=tazama-lf/${what#tazama-};    dest=vendor/tazama/${what#tazama-}; prune=(.husky .vscode) ;;
  *) echo "unknown target $what"; exit 1 ;;
esac
tmp=$(mktemp -d)
if [[ "$tag" =~ ^[0-9a-f]{40}$ ]]; then
  git init -q "$tmp/src" && git -C "$tmp/src" fetch -q --depth 1 "https://github.com/$repo.git" "$tag" && git -C "$tmp/src" checkout -q FETCH_HEAD
else
  git clone -q --depth 1 --branch "$tag" "https://github.com/$repo.git" "$tmp/src"
fi
sha=$(git -C "$tmp/src" rev-parse HEAD)
rm -rf "$dest" && mkdir -p "$dest"
(cd "$tmp/src/$keep" && tar --exclude=.git -cf - .) | tar -xf - -C "$dest"
[ -z "$keep" ] || cp "$tmp/src/LICENSE" "$dest/LICENSE"
# Some Tazama repos declare Apache-2.0 in every SPDX header and package.json but ship no LICENSE file: add the text.
if [ ! -e "$dest/LICENSE" ] && [ -f "$dest/package.json" ] && grep -q '"license": *"Apache-2.0"' "$dest/package.json"; then
  cp vendor/licenses/Apache-2.0.txt "$dest/LICENSE"; echo "added Apache-2.0 LICENSE (declared in package.json and SPDX headers)"
fi
rm -rf "$dest/.github" "$dest/.circleci" "$dest/CLAUDE.md" "$dest/AGENTS.md" "$dest/.claude" "$dest/.cursor" "$dest/.devcontainer"
find "$dest" -name CLAUDE.md -o -name AGENTS.md | xargs -r rm -f
# Private keys (upstream dev TLS stores and the like) are never committed, wherever they sit in the tree.
${PYTHON:-python3} ci/find-private-keys.py "$dest" | while IFS= read -r k; do echo "dropped private key: $k"; rm -f "$k"; done
find "$dest" -name '*.key' -size +0 -print -delete   # key files with other encodings
for p in "${prune[@]}"; do rm -rf "${dest:?}/$p"; done
rm -rf "$tmp"
# DIFME's patches to this target (vendor/patches/<target>/*.patch, applied in order; each states its reason).
for p in vendor/patches/"$what"/*.patch; do
  [ -e "$p" ] || continue
  patch -s -p1 -d "$dest" < "$p" && echo "applied $p"
done
${PYTHON:-python3} - "$what" "$repo" "$tag" "$sha" "${prune[*]:-}" "$keep" <<'PY'
import json, sys, pathlib
what, repo, tag, sha, prune, keep = sys.argv[1:]
p = pathlib.Path("vendor/VENDORED.json")
data = json.loads(p.read_text()) if p.exists() else {}
entry = {"upstream": f"https://github.com/{repo}", "tag": tag, "commit": sha}
if tag == sha: entry["tag"] = "(no release tag; pinned by commit)"
if prune.strip(): entry["omitted"] = prune.split()
if keep: entry["kept_only"] = keep
data[what] = entry
p.write_text(json.dumps(data, indent=2) + "\n")
PY
echo "vendored $repo@$tag ($sha) into $dest"

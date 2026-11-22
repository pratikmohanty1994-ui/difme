#!/usr/bin/env bash
# Builds one Tazama service from vendor/tazama (ADR-023) with production dependencies only, for the image's run stage.
# Usage (from a copy of vendor/tazama): build.sh <service> [rule]   e.g. build.sh rule-executer rule-902
# Libraries first (frms-coe-lib's build copies its .proto files into lib/), then the rule a rule-executer packages,
# then the service. --install-links installs each vendored library like a registry package, with its own dependencies,
# so nothing comes from GitHub's token-gated registry. Result: <service>/{build,node_modules,package.json}.
set -euo pipefail
service=$1 rule=${2:-rule-901}
# A rule is upstream's (vendor/tazama/<rule>) or DIFME's own (services/fraud-rules/<rule>, ADR-023); the image build
# copies both trees in their repository layout and runs from vendor/tazama.
if [ -d "$rule" ]; then ruledir=$rule; else ruledir=../../services/fraud-rules/$rule; fi
# Lifecycle scripts are skipped (upstream's `prepare` runs husky, a git-hooks tool, absent outside a dev checkout);
# the one install script needed, the Kafka client's native-module download, is run explicitly where it is present.
native() { if [ -d node_modules/@confluentinc/kafka-javascript ]; then npm rebuild @confluentinc/kafka-javascript --loglevel=error; fi; }
# npm runs a file: dependency's `prepare` script when it packs it, even with --ignore-scripts; upstream's runs husky
# (git hooks), which rule-901 doesn't even depend on. This script runs on a build copy, so the hooks go first.
for pkg in */package.json; do (cd "$(dirname "$pkg")" && npm pkg delete scripts.prepare); done
npm_ci() { npm ci --install-links --ignore-scripts --no-audit --no-fund --loglevel=error && native; }
for lib in frms-coe-lib frms-coe-startup-lib auth-lib tcs-lib; do
  (cd "$lib" && npm_ci && npm run build)
done
if [ "$service" = rule-executer ]; then
  (cd "$ruledir" && npm_ci && npm run build && if [ "$ruledir" != "$rule" ]; then npm test; fi)  # DIFME rules are tested on every image build
  cd rule-executer
  if [ "$rule" = rule-901 ]; then
    npm_ci
  else
    # The lockfile pins rule-901, and npm keeps a locked entry even when package.json changes; naming the dependency
    # on the command line re-resolves just that one.
    npm ci --install-links --ignore-scripts --no-audit --no-fund --loglevel=error
    npm install --install-links --ignore-scripts --no-audit --no-fund --loglevel=error "rule@file:../$ruledir" && native
  fi
else
  cd "$service"
  npm_ci
fi
npm run build
npm prune --omit=dev --install-links --no-audit --no-fund --loglevel=error
test -f build/index.js
if [ "$service" = rule-executer ]; then
  packaged=$(node -p "require('./node_modules/rule/package.json').name")
  expected=$(node -p "require('../$ruledir/package.json').name")
  [ "$packaged" = "$expected" ] || { echo "packaged $packaged, expected $expected" >&2; exit 1; }
fi
echo "built $service${2:+ with $rule}: $(du -sh node_modules | cut -f1) of production dependencies"

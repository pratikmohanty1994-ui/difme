# Tazama (vendored, ADR-023)

Pinned v4.0.x releases of thirteen tazama-lf repositories (tcs-lib added for admin-service), recorded in `vendor/VENDORED.json` and re-vendored with
`ci/vendor-sync.sh tazama-<repo> <tag>`. Apache-2.0; the LICENSE text was added where only `package.json` and the
SPDX headers carried it.

## DIFME patches (vendor/patches/tazama-<repo>/, re-applied by vendor-sync; diffs against the pristine release)
| Repo | Patch | Why |
|---|---|---|
| frms-coe-lib | 0001-opentelemetry-and-stdout-logs | OpenTelemetry (OTLP gRPC to Alloy → Tempo) in place of Elastic APM, same `Apm` API so no service changes (Elastic-only options accepted and ignored); `APM_URL` is the OTLP endpoint. Logs to stdout only (Alloy → Loki); the Elasticsearch stream and its dependencies are removed. `tslib` becomes a runtime dependency (upstream bug: the compiled lib requires it). |
| frms-coe-startup-lib | 0001-kafka-transport | Kafka transport (`STARTUP_TYPE=kafka`) in place of NATS: DIFME already runs Kafka. Live test: `node __tests__/kafka-live.cjs` against a real broker. |
| every other repo | 0001-local-dependencies | `@tazama-lf/*` dependencies as `file:` links to the vendored copies (`ci/tazama-local-deps.py`) and no GitHub registry line in `.npmrc`: upstream publishes the libraries only on GitHub's token-gated npm registry. rule-executer's `rule` alias points at `rule-901`; an image swaps in the rule it packages. |

Lockfiles are not in the patches: after re-vendoring, run `python3 ci/tazama-local-deps.py` and
`npm install --install-links` in each package (libraries first) to regenerate them.

## Verified (2026-11-22, built from source, no GitHub registry)
Tests: frms-coe-lib 205, tcs-lib 1, auth-lib 46, auth-lib-provider-keycloak 24, rule-901 25, rule-902 25, tms-service
47, event-director 67, rule-executer 16, typology-processor 63, event-adjudicator 53, admin-service 1314 — all pass.
auth-lib's tests need a key pair at `./private-key.pem` / `./public-key.pem`; vendoring drops upstream's committed test
key (no private keys in the repo), so generate a throwaway pair before running them.

## Building
`npm install --install-links && npm run build`, in this order: frms-coe-lib (its build copies the `.proto` files
into `lib/`), frms-coe-startup-lib, auth-lib, tcs-lib, then the rules, the Keycloak provider and the services.
`--install-links` installs each linked library like a registry package, with its own dependencies.

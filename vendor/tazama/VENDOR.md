# Tazama (vendored, ADR-023)

Pinned v4.0.x releases of twelve tazama-lf repositories, recorded in `vendor/VENDORED.json` and re-vendored with
`ci/vendor-sync.sh tazama-<repo> <tag>`. Apache-2.0; the LICENSE text was added where only `package.json` and the
SPDX headers carried it.

## DIFME patches (vendor/patches/tazama-<repo>/, re-applied by vendor-sync)
| Repo | Patch | Why |
|---|---|---|
| frms-coe-startup-lib | 0001-kafka-transport | Kafka transport (`STARTUP_TYPE=kafka`) in place of NATS: DIFME already runs Kafka. `@tazama-lf/frms-coe-lib` resolves to `../frms-coe-lib` (upstream publishes it only on GitHub's token-gated npm registry). Live test: `node __tests__/kafka-live.cjs` against a real broker. |

## Building
`npm ci && npm run build` in `frms-coe-lib` first (its build copies the `.proto` files into `lib/`), then the
libraries and services that depend on it.

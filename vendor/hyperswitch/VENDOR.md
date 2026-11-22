# Juspay Hyperswitch (vendored)

PSP (PA/PG) simulator for DIFME (owner decision 2026-11-21). Upstream https://github.com/juspay/hyperswitch, tag
`v1.129.0`, commit in `vendor/VENDORED.json`. Licence: Apache-2.0 (`LICENSE`).

Left out (not part of the Cargo workspace): `docs/`, `postman/`, `cypress-tests/`, `api-reference/`.

Local changes (patch files in `vendor/patches/hyperswitch/`, re-applied by `ci/vendor-sync.sh`):
- `0001-v1-without-common-default`: the router's `v1` feature no longer implies `common_default` (`default` still lists
  it, so upstream's default build is unchanged). Lets DIFME's image build only what it uses and fit 16 GB runners:
  no payouts, no `frm` (external paid FRM services only; fraud and FRM are Tazama, ADR-023), no Stripe compatibility
  layer, no KV store.

How DIFME runs it:
- Image: `deploy/images/hyperswitch/Dockerfile` builds `router` with the default features (v1 + dummy connector).
- Config: the upstream `config/docker_compose.toml`, with DIFME's hosts and secrets as `ROUTER__*` environment
  overrides (`deploy/platform/rails/hyperswitch/hyperswitch.yaml`).
- Schema: `deploy/images/hyperswitch/migrate.sh` applies `migrations/` with psql and records versions in diesel's
  `__diesel_schema_migrations`, so diesel_cli could take over unchanged.

Reviewed: `crates/router/src/services/encryption.rs` embeds RSA test keys inside `#[cfg(test)]` (unit-test
fixtures, not compiled into the router). Kept: removing them means editing upstream source.

Infrastructure it expects and the DIFME component used instead: `docs/architecture/component-reuse.md`.

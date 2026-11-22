# Juspay Hyperswitch (vendored)

PSP (PA/PG) simulator for DIFME (owner decision 2026-11-21). Upstream https://github.com/juspay/hyperswitch, tag
`v1.129.0`, commit in `vendor/VENDORED.json`. Licence: Apache-2.0 (`LICENSE`).

Left out (not part of the Cargo workspace): `docs/`, `postman/`, `cypress-tests/`, `api-reference/`.

Local changes: none. (A 2026-11-22 patch to build without payouts/frm/kv_store was dropped: upstream does not
compile with those features off, so it saved nothing.)

How DIFME runs it:
- Image: `deploy/images/hyperswitch/Dockerfile` builds `router` with the default features, one crate at a time, router at opt-level 0 (memory: docs/knowledge-base/build.md).
- Config: the upstream `config/docker_compose.toml`, with DIFME's hosts and secrets as `ROUTER__*` environment
  overrides (`deploy/platform/rails/hyperswitch/hyperswitch.yaml`).
- Schema: `deploy/images/hyperswitch/migrate.sh` applies `migrations/` with psql and records versions in diesel's
  `__diesel_schema_migrations`, so diesel_cli could take over unchanged.

Reviewed: `crates/router/src/services/encryption.rs` embeds RSA test keys inside `#[cfg(test)]` (unit-test
fixtures, not compiled into the router). Kept: removing them means editing upstream source.

Infrastructure it expects and the DIFME component used instead: `docs/architecture/component-reuse.md`.

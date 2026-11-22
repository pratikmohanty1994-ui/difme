# DoItForMe (DIFME)

A cloud-native, event-sourced platform built on the **Financial Platform Architecture v1.2** pattern:
CQRS · Event Sourcing · CRDT · Saga · DDD · Formal Verification · Zero-Trust · GitOps.

Everything runs remotely. Open in GitHub Codespaces, then pick the layers you want running:

```bash
make cluster                 # k3d cluster + Argo CD inside the Codespace
make up PROFILE=core         # ingress, security, cache, database, temporal, core services
make up PROFILE=streaming    # Kafka KRaft, Debezium, RisingWave, Flink, Apicurio, KEDA
make status                  # what is running
make down PROFILE=streaming  # free memory for the next layer
```

A free Codespace has up to 4 cores and 16 GB of RAM, so run 1–2 profiles at a time. CI runs every profile in ephemeral clusters.

## Profiles (11 layers)

| # | Layer | Profile | Path |
|---|-------|---------|------|
| 1 | Edge | `edge` (Android emulator) | `edge/` | ✅ verified on a cluster |
| 2 | Hub / Gateway | `hub` | `services/hub/` | ✅ verified on a cluster |
| 3 | Core Platform (CQRS) | `core` | `services/core/` | ✅ verified on a cluster |
| 4 | Workflow Engine | `core` | `deploy/platform/temporal/` | ✅ verified on a cluster |
| 5 | Database Tier | `core` + `data` | `deploy/platform/database-tier/` | ✅ verified on a cluster |
| 6 | Streaming & CDC | `streaming` | `deploy/platform/streaming/` | ✅ verified on a cluster |
| 7 | Deterministic Replay | `streaming` | `services/core/replay-engine/` | ✅ verified on a cluster |
| 8 | Lakehouse & Analytics | `lakehouse` | `deploy/platform/lakehouse/`, `analytics/` | ✅ verified on a cluster |
| 9 | Observability | `observability` | `deploy/platform/observability/` | ✅ verified on a cluster |
| 10 | Cost & FinOps | `observability` | `deploy/platform/opencost/` | ✅ verified on a cluster |
| 11 | Infrastructure | always | `deploy/bootstrap/`, `policies/` | ✅ verified on a cluster |
| — | AI / ML plane | `ml` | `deploy/platform/ml-platform/`, `ml/` |
| — | Back-Office UI | `backoffice` | `backoffice/` |
| — | Forms + business processes (ADR-008) | `process` | `vendor/formio/`, `processes/`, `forms/`, `services/core/process-gateway/` |
| — | Payment rails: PSP, CBS, payment hub, card scheme (ADR-022) | `rails` | `deploy/platform/rails/`, `services/scheme-sim/`, `services/core/payment-hub/`, `vendor/` |

## Coverage matrix — every component in the PDF

Status: ✅ installed and healthy on a cluster · 🟡 partly done (detail in the cell) · ❌ not started · 📋 tracked, not built by design. Live list of what's pending: `docs/status.md`.

Strict OSI licensing applies. Where the PDF names a non-OSI or paid component, the swap is listed with its reason (see [docs/architecture/decisions.md](docs/architecture/decisions.md)).

| PDF § | PDF component | DIFME implementation | Path | Status |
|---|---|---|---|---|
| 4.1 | Rancher / RKE2 / Fleet | k3d (dev) · RKE2-compatible manifests · Rancher Fleet `fleet.yaml` per bundle | `deploy/bootstrap/`, `deploy/fleet/` | ✅ verified on a cluster |
| 4.1 | Rancher Backup Operator → MinIO | Velero + **SeaweedFS** S3 (ADR-005) · RKE2 etcd snapshots every 6h | `deploy/platform/backup/` | ✅ verified on a cluster |
| 4.2 | ingress-system: nginx-ingress, cert-manager, external-dns, metallb | **Envoy Gateway** replaces nginx-ingress (ADR-005); others same | `deploy/platform/ingress-system/` | ✅ verified on a cluster |
| 4.3 | NLB / ALB / QUIC paths, WAF OWASP CRS 4.0 | MetalLB + Envoy Gateway (TLS 1.3) + **Coraza** CRS 4 · UDP 4443 → Quinn via UDPRoute | `deploy/platform/ingress-system/` | ✅ verified on a cluster |
| 4.4 | Istio mTLS STRICT, VirtualService canary, circuit breaker, retries, egress allowlist | **Istio Ambient** (ztunnel + waypoints, ADR-005) with the same policies | `deploy/platform/istio-system/` | ✅ verified on a cluster |
| 4.5 | Semgrep, Trivy, TLA+/TLC, Sigstore/cosign, SLSA L3, Karate, Newman, k6, Gatling, Locust, Playwright, Cypress, TestCafe, LLM test gen, Argo CD rollback, canary SLO gate, Pyroscope CI gate | Same gates in GitHub Actions + Argo Rollouts; testing consolidated to **Playwright, k6, Schemathesis** and the scheme simulator (ADR-014, ADR-022) | `.github/workflows/`, `tests/` | ✅ verified on a cluster (canary SLO gate: p99 ≤ 400 ms) |
| 4.5 | Financial message / scenario simulators | Card scheme + ISO 8583 adapter + acquirer on **moov-io/iso8583**; PSP **Hyperswitch**; CBS **Fineract**; payment hub on Temporal (ADR-022) | `services/scheme-sim/`, `services/core/payment-hub/`, `deploy/platform/rails/` | 🟡 partial (verified locally; cluster run pending) |
| 4.5 | Tekton | Tekton pipelines (on-cluster mirror of GitHub Actions) | `deploy/platform/tekton-pipelines/tekton/` | ✅ verified on a cluster |
| 4.6 | Cilium eBPF kube-proxy replacement, Hubble | Same (k3d with flannel disabled) | `deploy/platform/kube-system/cilium/` | ✅ verified on a cluster |
| 5.1 | Vue 3 + Rust (uniffi) app → **Tauri 2 mobile** (ADR-005), **Wasmtime** WASI P2 components (ADR-016) + ONNX, automerge-rs CRDT, StrongBox/KeyMint/Blake3, HCE HostApduService, WorkManager | Same | `edge/` | ❌ not started |
| 5.2 | Quinn hub, session manager, telemetry relay, tonic gRPC bridge, live dashboard relay, rustls+SPIRE, Pyroscope Rust | Same | `services/hub/` | 🟡 partial (hub service; session manager, relays, gRPC bridge to do) |
| 5.3 | quarkus-cmd-svc, qry-svc, saga-orchestrator, consistency-router, rate-limiter, rehydration-svc | Same, on **Java 25 LTS** (ADR-005) | `services/core/` | ✅ verified on a cluster |
| 5.4 | Hibernate 6 + Panache, outbox, MyBatis, Caffeine L1, Redisson JCache L2 | Same (L2 on Valkey) | `services/core/` | ✅ verified on a cluster |
| 5.5 | Event broker (Kafka API) | **Apache Kafka 4 (KRaft)** via Strimzi — OSI replacement | `deploy/platform/streaming/` | ✅ verified on a cluster |
| 5.5 | Debezium (CloudEvents), Flink, Apicurio, Airbyte, KEDA | Same, with **Apache SeaTunnel** instead of Airbyte (ELv2, ADR-009) | `deploy/platform/streaming/` | ✅ verified on a cluster |
| 5.5 | Streaming SQL views | **RisingWave** — OSI replacement | `deploy/platform/streaming/` | ✅ verified on a cluster |
| 5.6 | Iceberg, MinIO, Trino, Spark, StarRocks, dbt, Superset | SeaweedFS + Polaris (ADR-005); Spark covered by Flink + dbt (ADR-015); **StarRocks dropped, Trino serves analytics** (ADR-021) | `deploy/platform/lakehouse/`, `analytics/` | ✅ verified on a cluster |
| 5.7 | Feast, Weaviate, ONNX Runtime, PostgresML, FlinkML, MLflow | **pgvector instead of Weaviate** (ADR-021); PostgresML covered by MLflow + ONNX (ADR-015); server-side ONNX scorer parked until a model exists | `deploy/platform/ml-platform/`, `ml/` | 🟡 partial (fraud scorer and Tazama built; cluster run pending) |
| 5.7 | Fraud scoring and FRM | **Tazama** (vendored, ADR-023) on Kafka, shared Postgres/Valkey, OpenTelemetry; DIFME's ONNX model becomes a Tazama rule | `vendor/tazama/`, `deploy/platform/fraud/tazama/` | 🟡 partial (end to end locally; cluster run pending) |
| 5.8 | SPIFFE/SPIRE, Cilium, OPA Gatekeeper, Kyverno, Sigstore, OpenTelemetry, Alloy, DataHub + OpenLineage | **OpenLineage + Marquez instead of DataHub** (ADR-021), with **Kyverno as the single admission engine** (Gatekeeper and policy-controller removed, ADR-015) | `deploy/platform/security/`, `deploy/platform/governance/` | ✅ verified on a cluster |
| 5.8 | Secrets management | **OpenBao** — OSI replacement | `deploy/platform/security/` | ✅ verified on a cluster |
| 5.8 | Just-in-time access | **Warpgate** — OSI replacement | `deploy/platform/security/` | ✅ verified on a cluster |
| 5.9 | React 18 shell + Module Federation, Settlements (TanStack Query), Compliance (SvelteKit), Analytics (Angular 17 + ECharts), Zustand, Turborepo + pnpm, Tailwind tokens, Storybook, Bundlesize | Same design on **React 19 / Svelte 5 / Angular 20 + Module Federation 2.0 (Rspack)** (ADR-005) | `backoffice/` | ✅ verified on a cluster |
| 5.9 | Kong + APISIX | **Envoy Gateway** routes + JWT (Keycloak) + rate limits (ADR-015) | `deploy/platform/ingress-system/gateway-config/` | ✅ verified on a cluster |
| 5.10 | OpenAPI 4.0 | **OpenAPI 3.1** — 4.0 is unreleased | `api/openapi/` | ✅ verified on a cluster |
| 5.10 | AsyncAPI 3, CloudEvents 1.0, GraphQL SDL, proto3 + Buf, Apicurio, Swagger UI, AsyncAPI Studio | Same | `api/` | ✅ verified on a cluster |
| 6.1 | Temporal OSS | Same — persistence on **YugabyteDB YSQL** | `deploy/platform/temporal/` | ✅ verified on a cluster |
| 6.2 | KEDA lag scaler (100 / 10 / 2–50) | Same, Kafka scaler | `deploy/platform/streaming/keda/` | ✅ verified on a cluster |
| 6.3 | OpenFeature + flagd | Same | `deploy/platform/core-platform/flagd/`, `config/flags/` | ✅ verified on a cluster |
| 8 | TigerBeetle | Same | `deploy/platform/database-tier/tigerbeetle/` | ✅ verified on a cluster |
| 8 | Settlements DB (serializable, multi-region) | **YugabyteDB** (serializable, geo-partitioned tablespaces) — OSI replacement | `deploy/platform/database-tier/yugabytedb/` | ✅ verified on a cluster |
| 8 | YugabyteDB | Same | `deploy/platform/database-tier/yugabytedb/` | ✅ verified on a cluster |
| 8 | Audit log store | **Iceberg Day-0 archive** + YugabyteDB outbox (ADR-015) | `deploy/platform/streaming/flink-archive/` | ✅ verified on a cluster |
| 8 | FoundationDB | **YugabyteDB** serializable unique keys (ADR-015) | `deploy/platform/database-tier/yugabytedb/` | ✅ verified on a cluster |
| 8 | L2 cache + CRDT rate limits | **Valkey** (CRDT PN-counter implemented in Lua) — OSI replacement | `deploy/platform/cache-tier/` | ✅ verified on a cluster |
| 8 | Weaviate | **pgvector** on the shared Postgres (ADR-021) | `deploy/platform/database-tier/postgres-docdb/` | ✅ verified on a cluster |
| 9 | UUIDv7 idempotency at every layer, inbox/outbox | Same | `services/core/common/` | ✅ verified on a cluster |
| 7 / 9 | Deterministic replay + Semgrep purity gate | Same | `services/core/replay-engine/`, `policies/semgrep/` | ✅ verified on a cluster |
| 10 | VictoriaMetrics, Grafana, Loki, Tempo, Pyroscope, Alloy, Alertmanager, vmalert | Same | `deploy/platform/observability/` | ✅ verified on a cluster |
| 10 | Hosted load-test execution | **k6-operator** (self-hosted) — free replacement | `tests/perf/`, `deploy/platform/k6/` | ✅ verified on a cluster |
| 11.1 | RATS RFC 9334 (TEE, EAT, verifier) | **Veraison** verifier + software-simulated TEE in the emulator | `services/attestation/` | 🟡 partial (verifier; TEE belongs to the edge app) |
| 11.2 | Syft SBOM, Harbor, GUAC | Same | `.github/workflows/`, `deploy/platform/harbor/` | ✅ verified on a cluster |
| 13 | Scenarios A–D (on-prem, cloud, hybrid, QUIC proxy chain) | Kustomize overlays + OpenTofu modules (planned; Terraform is BSL) + local QUIC relay | `deploy/overlays/`, `infra/` (planned), `services/hub/quic-relay/` | ❌ not started |
| 14 | `@ConsistencyProfile` routing matrix | Same | `services/core/consistency-router/` | ✅ verified on a cluster |
| 16 | OpenCost cost-per-transaction | Same | `deploy/platform/opencost/` | ✅ verified on a cluster |
| 17 | v2.0 candidates | Tracked, not built | `docs/roadmap.md` | 📋 tracked |

## Repository layout

```
.devcontainer/   Codespaces environment
api/             OpenAPI, AsyncAPI, proto, GraphQL, CloudEvents contracts
analytics/       dbt, Flink jobs, Spark jobs, Superset
backoffice/      Turborepo micro-frontends
config/          Feature flags, consistency profiles
deploy/          Argo CD apps, Helm values, Kustomize overlays, profiles
docs/            Architecture, decisions, runbooks
edge/            Mobile app, Rust CRDT core, Wasmtime plug-ins, ONNX fraud model
infra/           OpenTofu modules for cloud scenarios B/C (planned; Terraform is BSL)
ml/              Fraud model training → ONNX, Feast definitions
policies/        Kyverno, OPA Rego, Semgrep rules
services/        core (Quarkus), hub (Rust), attestation
specs/tla/       TLA+ specifications, checked in CI
tests/           Playwright (UI + API), k6 (load), Schemathesis (contract)
vendor/          Pinned upstream sources built here (Form.io, Hyperswitch, Fineract, moov-io/iso8583)
```

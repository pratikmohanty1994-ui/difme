# Architecture Decision Records

DIFME follows Financial Platform Architecture v1.2. These records log every deviation from the PDF and the reason for it.

## ADR-001 — Strict OSI licensing
**Decision:** Every runtime component must carry an OSI-approved licence. The PDF claims "100% OSI", but several of the components it names have since changed licence.

| PDF role | Issue | Replacement | Licence | Notes |
|---|---|---|---|---|
| L2 cache + CRDT rate limits | Non-OSI licence | Valkey 8 | BSD-3 | PDF §8 already evaluates Valkey. The PN-Counter CRDT for rate limiting is a Lua script plus per-region counters (`services/core/rate-limiter`). |
| Secrets management | Non-OSI licence | OpenBao 2 | MPL-2.0 | Linux Foundation project. Dynamic DB creds TTL=1h, PKI, transit. |
| Just-in-time infra access | Non-OSI licence | Warpgate | Apache-2.0 | Identity-aware SSH/HTTP/DB bastion with session recording. |
| Streaming SQL views | Non-OSI licence | RisingWave | Apache-2.0 | Postgres-wire streaming SQL with incremental materialized views, Kafka source and sink. |
| Event broker (Kafka API) | Non-OSI licence | Apache Kafka 4 (KRaft) via Strimzi | Apache-2.0 | No ZooKeeper. Tiered storage: see ADR-006. Wasm transforms → Kafka Streams / Flink. |
| Settlements DB (serializable, multi-region) | Non-OSI licence | YugabyteDB 2.25 YSQL | Apache-2.0 | Serializable isolation, geo-partitioned tablespaces, Raft. Also the Temporal persistence backend. |
| Audit log store | Non-OSI licence | Apache Cassandra 5 | Apache-2.0 | Append-only audit log, quorum writes, SAI indexes. |

## ADR-002 — Non-existent or proprietary items
| PDF item | Issue | Replacement |
|---|---|---|
| OpenAPI 4.0 | Not released (the "Moonwalk" draft) | OpenAPI 3.1, with a CI gate (oasdiff) that blocks breaking changes |
| Financial message / scenario simulators | Not publicly available | Card-scheme simulator on moov-io/iso8583 (Apache-2.0) plus PSP, CBS and payment hub simulators (ADR-022; replaced the jPOS plan) |
| Hosted load-test execution | Paid SaaS | k6-operator (Apache-2.0) runs distributed tests in-cluster; results go via remote-write to VictoriaMetrics |
| Hardware TEE | Hardware needed | The Android emulator has no hardware-backed keystore, so a software-simulated TEE signs EAT tokens; the RATS verifier is Veraison (Apache-2.0) |
| Three active regions | Paid cloud | Three k3d clusters (or three namespaces with zone labels) simulate the regions; provider-neutral Terraform modules are in `infra/terraform/` |

## ADR-003 — Runtime environment
**Decision:** GitHub Codespaces (4 cores / 16 GB) is the only runtime; there is no always-on host. The platform is split into profiles that can be switched on and off. CI (GitHub Actions, which is free for public repos) runs each profile's integration tests in ephemeral k3d clusters.
**Consequence:** Throughput and latency SLAs in PDF §1.1 and §12 are design targets. They are measured by k6 in CI on shared runners, so absolute numbers will be lower than on production hardware.

## ADR-004 — Repo visibility
**Decision:** The repository is public. The PDF's "CONFIDENTIAL" marking is not carried into the repo. Secrets live only in GitHub Actions secrets, Codespaces secrets and OpenBao.

## ADR-005 — Newer free alternatives (owner-approved 2026-11-17)
The owner chose each of these when offered a newer free alternative to the PDF component.

| PDF component | Chosen | Reason |
|---|---|---|
| NGINX Ingress Controller + ModSecurity | **Envoy Gateway** (Gateway API) + **Coraza** WAF running OWASP CRS 4 | ingress-nginx was retired upstream (no fixes after March 2026). Gateway API is the Kubernetes standard and routes UDP/QUIC and HTTP/3 natively. |
| MinIO | **SeaweedFS** | MinIO community edition stopped shipping binaries and images and is in maintenance mode. SeaweedFS is Apache-2.0, S3-compatible, has erasure coding and replication, and is light enough for a Codespace. |
| Istio with sidecars | **Istio Ambient** (ztunnel + waypoints) | GA since 1.24 and much lighter (PDF §17 candidate). mTLS STRICT, L7 policy, canary and circuit breaking keep working through waypoints. |
| Java 21 | **Java 25 LTS** | Current LTS. Fixes virtual-thread pinning on `synchronized`, adds scoped values and compact object headers. |
| React 18 / Svelte 4 / Angular 17 + Webpack 5 Module Federation | **React 19 / Svelte 5 / Angular 20 + Module Federation 2.0 on Rspack** | The old majors are out of support. MF 2.0 adds manifest-based remotes and type hints, and Rspack builds faster. |
| Native Android shell + uniffi | **Tauri 2 mobile** (Vue 3 UI + Rust core; Kotlin plugins for HCE/NFC/KeyStore) | One Rust codebase shared with the hub, first-class Android and iOS. |
| Iceberg catalog (unspecified) | **Apache Polaris** (Iceberg REST) | One catalog with RBAC and credential vending for Trino, Spark and Flink (StarRocks dropped, ADR-021). |
| Kong + APISIX | **Kept as in the PDF** | Owner's choice: Kong external, APISIX back-office, both behind Envoy Gateway. |

## ADR-006 — Kafka tiered storage (decided 2026-11-17)
The PDF tiers old broker segments to object storage. Apache Kafka has the KIP-405 interface but no built-in S3 RemoteStorageManager; the available Apache-2.0 plugins are published by vendors.
**Current state:** event topics keep infinite local retention, and Flink archives every event to Iceberg on SeaweedFS (Day-0 history). **Decision (owner):** no KIP-405 plugin. Infinite retention plus the Flink→Iceberg archive is the tiering mechanism, which avoids vendor-named plugins.

## ADR-007 — Backups (decided 2026-11-17)
**Decision (owner):** keep Velero for cluster backup to SeaweedFS S3. The vendor word in its S3 plugin is accepted as a technical identifier.

## ADR-008 — Dynamic forms and business-process engine (owner-approved 2026-11-17)
These are additions to the PDF requested by the owner.

| Concern | Decision | Licence | Notes |
|---|---|---|---|
| Dynamic forms with user-defined metadata | **formio** open-source server **v4.11.0** + **formio.js v5.7.0** builder/renderer, **vendored** into `vendor/formio/` at pinned tags | OSL-3.0 (server), MIT (js) | The hosted SaaS was rejected (paid after trial). The source lives in this repo, is built into our own signed images, and is updated with `ci/vendor-sync.sh`. OSL-3.0 requires publishing modifications when deployed, which this public repo satisfies. |
| formio database | **FerretDB 2.7** on **PostgreSQL + DocumentDB extension** | Apache-2.0 / PostgreSQL / MIT | MongoDB Community is SSPL (not OSI). FerretDB speaks the MongoDB wire protocol. formio's own test suite runs against it in CI to catch gaps. |
| Business processes, human tasks, business rules | **Fluxnova 3.1.1** (FINOS fork of the Camunda 7 CE engine): BPMN 2.0, DMN, CMMN 1.1 | Apache-2.0 | CMMN is deprecated upstream and kept for backward compatibility only. Persistence is on PostgreSQL (officially supported). |
| Responsibility split (owner design) | **Fluxnova** owns business configuration and rules as DMN (limits, thresholds, eligibility, routing), **form-field constraints and dependencies** (required/visible/allowed values/ranges, cross-field rules) and human-centric BPMN. **Temporal** owns all orchestration between processes and services. Technical config and kill switches stay in flagd and GitOps. | — | Each formio form's metadata pins `decisionKey` + `decisionVersion`. A `form-rules` endpoint evaluates the DMN (debounced, cached by input hash) while the user types, and the same DMN is re-evaluated authoritatively on submit. |
| Temporal vs Fluxnova | **Both, split by purpose.** Temporal runs system sagas (payments, transfers; TLA+-verified). Fluxnova runs business processes: approvals, KYC/onboarding, disputes, and DMN rules editable by operations. | — | A Fluxnova external-task worker (`services/process/temporal-bridge`) can start Temporal workflows. |
| Process UI | **Process Studio** back-office micro-frontend: in-browser BPMN/DMN modelling with the **Apache KIE standalone editors**, a Fluxnova properties panel (assignee, formKey, decisionRef, external-task topic), deploy to engine, task inbox rendering formio forms, process monitoring. Fluxnova Cockpit/Tasklist/Admin are deployed for operations. | Apache-2.0 | bpmn-js/dmn-js were rejected because their licence requires a visible watermark (rule: open source with no limitations). |

## ADR-009 — Rule: open source and free with no limitations (owner, 2026-11-17)
Every component must be OSI-approved **and** free to use with no limitations: no watermark or attribution-display duties, no BSL/SSPL/ELv2/source-available licences, no usage-capped free tiers or paid feature gates. Copyleft (GPL/AGPL/OSL/MPL) is allowed; it imposes sharing obligations, not usage limits.

Applying the rule:
| Component | Problem | Replacement |
|---|---|---|
| bpmn-js / dmn-js | Watermark required | Apache KIE BPMN/DMN standalone editors (Apache-2.0) |
| Airbyte (PDF §5.5) | Platform under Elastic License v2 | **Apache SeaTunnel** (Apache-2.0): 100+ connectors incl. CDC, Zeta engine or Flink, web UI |

Unavoidable platform quota: GitHub Codespaces' free hours (Actions is unlimited for public repositories). No free hosting removes this.

## ADR-010 — Back-office stack and identity (owner-approved 2026-11-17)
| Concern | Decision | Licence |
|---|---|---|
| Identity provider (OIDC/SAML, LDAP federation, RBAC — PDF §4.1 "LDAP/OIDC") | **Keycloak 26.8.2**, realm `difme` with groups compliance / settlements / analytics / ops / process-designers | Apache-2.0 |
| Shell + React remotes | React 19.3, Module Federation 2.9 on Rsbuild/Rspack, TanStack Query, Zustand, Tailwind CSS 4 tokens | MIT |
| Compliance remote | **Svelte 5** exposed through Module Federation as a `mount(el, props)` function. SvelteKit's SSR router is not used inside a federated remote. | MIT |
| Analytics remote | **Angular 22** (latest; the plan said 20) + ECharts 6, shipped as an Angular Elements web component `<difme-analytics>` loaded by the shell's remote registry. Angular's builder is not Rspack, so a framework-neutral custom element is the integration contract. | MIT / Apache-2.0 |
| Process Studio / form builder | Apache KIE BPMN/DMN standalone editors 10.2 (lazy-loaded); vendored formio.js builder/renderer | Apache-2.0 / MIT |
| Auth in browser | oidc-client-ts (Authorization Code + PKCE); the token is shared with remotes through the singleton `@difme/auth` store | Apache-2.0 |
| Feature flags in browser | OpenFeature web SDK + OFREP provider → flagd | Apache-2.0 |

Performance budget (PDF §5.9): each remote's **initial** JS must be ≤ 200 KB compressed (CI gate). The KIE editors and the formio builder are larger, so they load lazily on first use and are excluded from the initial budget.

## ADR-011 — Bulk file processing (owner-approved 2026-11-17)
**Requirement:** CSV, flat (fixed-width), JSON and Excel files of about 10M records, fully processed in **≤ 5 minutes** (≈ 33k records/s sustained, end to end). Every record is validated against linked records in the database and against DMN business rules.

**Decision:** an **Apache Flink batch job** (operator already deployed) with:
- **Parallel reading.** File splits for CSV/JSON-lines/fixed-width; every record id is `sha256(file):byteOffset`. Excel goes through Apache POI's streaming reader (`ExcelToCsv`, constant memory) to CSV first, because Excel can't be split.
- **Hybrid DB validation.**
  - Static reference data (account master, products, limits) is snapshotted into keyed in-memory state at job start, with one partitioned bulk scan.
  - Volatile checks (balances, duplicates, status) are **batched async lookups** (≈1,000 keys per `IN` query) against YugabyteDB follower replicas. There is never one query per record.
- **Rules.** The Fluxnova DMN engine is embedded in the operators. The pinned decision version is compiled once per job and evaluated in-process (µs per record), using the same DMN as the forms (ADR-008).
- **Idempotency.** Record ids are derived from the file SHA-256 plus the line number (UUIDv7-compatible), so re-running a file never double-applies.
- **Outputs.**
  - Valid records → batched sinks: TigerBeetle (≤ 8,190 per batch), Kafka or Iceberg.
  - Rejected records → error file with line number + reasons.
  - Run report → back-office.

**Throughput caveat:** writing 33k rows/s *into YugabyteDB* needs a multi-node cluster. The single-node Codespace cluster can't sustain it. The 5-minute target is measured by a CI benchmark on a generated 10M-record file, and the measured figure is published rather than assumed.

## ADR-012 — Efficiency rule and service runtimes (owner-approved 2026-11-17)
**Rule:** everything must be extremely lightweight (low RAM/CPU/I/O) even with the whole platform running, while keeping maximum throughput and minimum latency. Numbers are measured in CI, not assumed.

**Runtimes (hybrid):**
| Services | Runtime | Why |
|---|---|---|
| rate-limiter, consistency-router, projection-svc, replay-engine | **Native image** (Mandrel, GPLv2+CE) | ~25–50 MB RSS, ~50 ms start; these are I/O-bound, so JIT peak speed matters little |
| cmd-svc, qry-svc, saga-orchestrator, rehydration-svc, process-gateway | **JVM 25 + AOT cache** (JEP 483/514/515), compact object headers, tuned GC | Hot paths keep JIT peak throughput; JNI clients (TigerBeetle, FoundationDB) and Temporal are simpler on the JVM; the AOT cache removes most warm-up |
Each service's RSS, startup and throughput are recorded by CI and compared against the previous build.

**Measured (CI, 2026-11-17):** native images built for rate-limiter, consistency-router, projection-svc and replay-engine. process-gateway moved to JVM + AOT cache: the Temporal SDK's shaded gRPC/Netty fails native-image analysis (`ApplicationProtocolConfig` in the image heap). Revisit once the SDK ships native-image metadata.
Bulk benchmark (ADR-011), 10M records with DB + DMN validation on a 4-vCPU runner: **855 s → 56 s (178,571 records/s)** after the JVM-shared account snapshot, memoised DMN, flat POJO records and per-partition counting.

## ADR-013 — Cilium data path in the Codespace (verified live 2026-11-17)
Inside k3d (Kubernetes-in-Docker on a Codespace), Cilium's full kube-proxy replacement left host-network pods unable to reach ClusterIP services, even with legacy host routing and cgroup-root changes. The node-agent namespaces depend on that path.
**Decision:** the Codespace cluster runs Cilium **alongside k3s kube-proxy**. eBPF networking, network policy (L3–L7), WireGuard and Hubble stay. Real clusters (RKE2 on VMs or bare metal, `deploy/fleet/rke2-config.yaml` with `disable-kube-proxy`) use `kubeProxyReplacement: true` for the full eBPF service data path (PDF §4.6), where it is supported natively.

**Live base-profile measurements (Codespace, 4 cores / 16 GB, 2026-11-17):** 13/13 apps Synced+Healthy.
Excluding high-churn objects from Argo CD (policy reports, Gatekeeper status, Cilium endpoints, leases/events), status-only update suppression, a 300 s reconcile and a 300 s Gatekeeper audit reduced Argo CD's controller from ~300–900m bursts to **4–6m** and Gatekeeper from ~120–400m to **~5m**. The node idles at **0.22–0.68 cores, ~4.9 GB**.

## ADR-014 — Testing toolset: lean 4 (owner-approved 2026-11-17)
PDF §4.5 lists nine overlapping tools. Each capability is covered once:
| Capability | Tool | Replaces |
|---|---|---|
| UI cross-browser E2E, visual regression, API functional | **Playwright** | Cypress, TestCafe, Karate, Newman |
| Load / performance (in-cluster via k6-operator, results to VictoriaMetrics) | **k6** | Gatling, Locust |
| Contract + generated tests from OpenAPI / GraphQL specs | **Schemathesis** | LLM-based test generation (paid API; non-deterministic) |
| ISO 8583 / financial message simulation | **scheme simulator on moov-io/iso8583** (ADR-022; was jPOS) | MSGSIM / FINSIM |
Unit tests stay in each stack's native runner (JUnit 5, Vitest, Rust `cargo test`). Fewer tools mean less CI time, fewer images and less RAM (ADR-012).

## ADR-015 — Remove redundant components (owner-approved 2026-11-17)
| Removed | Covered by | Saving |
|---|---|---|
| OPA Gatekeeper, Sigstore policy-controller | **Kyverno** (validate/mutate/generate + signed images, SLSA and SBOM attestations); the 2 Gatekeeper constraints were ported (`restrict-registries`, `no-plaintext-secrets`) | 2 controllers and their webhooks |
| Kong, APISIX | **Envoy Gateway**: Gateway API routes, URL rewrites, JWT verification against Keycloak (SecurityPolicy), rate limits and timeouts (BackendTrafficPolicy). One proxy hop instead of two. | 2 proxies; supersedes the "keep Kong + APISIX" row of ADR-005 |
| FoundationDB (+ operator) | **YugabyteDB** serializable unique-key table `core.idempotency_key` (same contract as `specs/tla/Idempotency.tla`); LINEARIZABLE → YugabyteDB | about 1 GB, plus the cluster-file plumbing |
| Cassandra (+ k8ssandra operator) | **Iceberg** Day-0 archive (audit history, time travel) + YugabyteDB outbox for recent events; APPEND_ONLY → Iceberg | about 2 GB |
| Spark operator | Flink (batch + streaming) and dbt on Trino | 1–2 GB when running |
| PostgresML | MLflow + ONNX serving | about 1 GB |
| Argo CD's bundled Dex | Keycloak | 1 pod |

Kept on purpose:
- **Temporal + Fluxnova:** system orchestration vs business processes.
- **RisingWave + Flink:** serving SQL views vs CEP and sinks.
- ~~**Trino + StarRocks:** federated SQL vs OLAP.~~ Superseded by ADR-021: Trino only.
- **Loki/Tempo/Pyroscope:** logs, traces, profiles.
- **Harbor/Tekton/Fleet/external-dns:** the owner had no preference.

## ADR-016 — WASI Preview 2 plug-ins on Wasmtime; CRDT merge verified (owner-approved 2026-11-18)
- **Promoted from PDF §17 (v2.0).** Sandboxed plug-in logic (fraud rules, limit checks) ships as WASI Preview 2 components. They run on **Wasmtime** (Bytecode Alliance, Apache-2.0), embedded in Rust in the Tauri edge app and the QUIC hub.
- **Why not WasmEdge (the PDF's choice):** Wasmtime is the reference implementation of WASI Preview 2 and the component model, so it has the most complete support; WasmEdge's lags.
- **Also promoted:** `specs/tla/CrdtMerge.tla` verifies offline edge spending as an escrow ("bounded counter") CRDT. The edge's automerge document carries this counter. A mutation test confirms the spec catches overspending.

## ADR-017 — Error-handling and resilience standard (owner-approved 2026-11-18)
**Distributed transactions:** Temporal sagas only, no separate LRA coordinator. Temporal provides LRA semantics (start, complete, compensate) with durability.
- Forward steps retry a bounded number of times with backoff.
- **Compensations retry until they succeed** (unlimited attempts, capped backoff), so a refund can never give up. Compensations are idempotent, and their failures are counted and alerted.

**Idempotency (three layers):**
- **Command:** the UUIDv7 `Idempotency-Key` is claimed **in the same transaction** as the payment and its outbox event. Before this, a failed write left the key claimed with no payment behind it.
- **Side effects:** step-derived ids (`StepIds`) make TigerBeetle transfers and events duplicate-safe.
- **Saga:** workflow id = payment id with `REJECT_DUPLICATE`, so no second run can start, even after the first finishes.
- **Consumers:** the inbox table.

**Transactional outbox:** payment + outbox row in one transaction; Debezium relays it to Kafka.
- The relay never skips records: `errors.tolerance: none`, retries for 10 min, idempotent producer, `acks=all`. A stopped relay is alerted.
- **Recovery sweeper:** accepted payments whose dispatch never finished (crash, timeout, open circuit) are re-dispatched every 15 s. Safe because every step is idempotent; the backlog is alerted.

**Database conflicts:** `TxRetry` re-runs the whole transaction on SQLSTATE 40001/40P01 (YugabyteDB serializable) with full-jitter backoff. Nothing else is retried.

**Synchronous calls** use SmallRye Fault Tolerance: every outbound call has a timeout, a circuit breaker and a bulkhead.
- **Retries** only for idempotent calls (ledger by transfer id, saga start), with jitter. Business rejections are neither retried nor counted as failures.
- **Rate limiter:** not retried (an acquire isn't idempotent). On failure it falls back to a conservative per-pod token bucket, so an outage degrades throughput instead of stopping payments or removing the limit.

**Throttling, layered:**
- **Gateway:** fixed per-route rate limits.
- **Service:** an adaptive concurrency limit (AIMD on latency) sheds excess with 503 + `Retry-After` instead of queueing.
- **Shared:** the per-account rate limiter.
- **Kafka consumers:** bounded polls with pause/resume (backpressure).

**Messaging failures:**
- **Transient:** a retry ladder of delay topics (1 s, 10 s, 60 s), then the DLQ.
- **Poison messages:** straight to the DLQ.
- **DLQ records** keep the original headers plus reason, cause, source topic/partition/offset and a retryable flag. The source offset commits only after the DLQ write is acknowledged.

**Observability:** every degraded path has a metric and an alert. That covers circuit opened, bulkhead rejecting, rate limiter degraded, load shedding, dispatch backlog, stuck compensation, DLQ growth and outbox relay down.

**Lifecycle:** 20 s graceful shutdown. Outbound HTTP clients have connect and read timeouts.

**Still to do:**
- **Gateway:** Envoy Gateway circuit breaking, outlier detection and retries for idempotent GETs, validated against the live CRDs.
- **Tooling:** a DLQ inspect/replay API in replay-engine.
- **Coverage:** the same treatment for the remaining consumers and services.

## ADR-018 — DIFME product scope and DiscountAI integration choices (owner-approved 2026-11-18)
Source documents: DIFME PRD/FRD v1.0 and DiscountAI E2E Architecture v4.1. The financial platform built so far is the substrate.
- **Order of work:** platform items first (section B: hub, edge app, ML), then the DiscountAI vertical slice (FR-01).
- **External rails:** a port (interface) per rail, with an open-source simulator behind it. Covered rails: card-network agentic credentials (two networks), network tokenization services, RBI-licensed PA escrow, merchant PSP checkout (UCP/ACP), UPI. ISO 8583 0100/0110 runs through the card-scheme simulator (ADR-022). Real providers plug in later without changes elsewhere.
- **Matching engine** (SBBA auction, CLOB, 50 ms window, < 5 ms p99): Java 25 with Aeron + SBE + Agrona (zero-GC hot path). Aeron Cluster provides a Raft-replicated, deterministic order book. This replaces the documents' Rust choice, because Aeron's first-class clients are Java and C.
- **Licence swaps** (hard rule, see ADR-009): the documents name CockroachDB (source-available since 2024), DragonflyDB (BSL 1.1) and Redpanda (BSL). They map to **YugabyteDB**, **Valkey** and **Apache Kafka**, all already in the platform.

## ADR-019 — Temporal persists on the shared platform Postgres (owner-approved 2026-11-18)
- **Why:** Temporal's visibility schema creates multi-column GIN indexes. YugabyteDB's `ybgin` doesn't support them (found live), and Temporal doesn't officially support YugabyteDB.
- **Change:** the PostgreSQL 17 instance that already hosts FerretDB, Fluxnova and Keycloak moves into the core profile as the **shared platform Postgres**. It now also hosts Temporal's default and visibility stores, under a `temporal` role without CREATEDB.
- **Unchanged:** YugabyteDB remains the system of record for payments, the outbox and idempotency. One extra small instance (limit 768 Mi) serves every component that needs plain PostgreSQL semantics.
- **Amendment (owner-approved 2026-11-18):** RisingWave's meta store moves here as well. Its sea-orm migrations
  fail on YugabyteDB: DDL is slow, the init migration is re-applied after being recorded, and the process crashes.
  Apicurio initialises cleanly on YugabyteDB and stays there. In the same decision, SeaweedFS (S3) moves from the
  lakehouse profile into streaming, because Flink checkpoints and the RisingWave state store need it.
- **Amendment (owner-approved 2026-11-20):** Harbor's database moves here from YugabyteDB. Harbor supports PostgreSQL
  only, and its first schema migration failed on YugabyteDB, leaving the migration "dirty" (cluster-verify). Role and
  database come from the `40-harbor.sh` init script; the password is the `harbor-db` Secret in both namespaces.

## ADR-020 — One vertical kernel, nine vertical packs; DiscountAI built in parallel (owner-approved 2026-11-18)
Source: the DiscountAI prototype (browser-only React simulation, DMN rules, evidence chains), E2E architecture v4.1 and
DIFME PRD §3–5. The prototype becomes the real system, and its pipeline is generalised for all nine verticals.
- **Order of work:** DiscountAI (FR-01) and the platform items (hub, edge app, ML) proceed **in parallel**. This updates ADR-018's ordering.
- **Kernel + packs:** `services/core/exchange-kernel` implements the shared pipeline as pure JDK code: FR-17 universal score,
  FR-14 collateral, FR-15 slashing, FR-16 value-weighted EWMA, conservation identity, and evidence chains format-compatible
  with the prototype. Each vertical is a declarative pack in `verticals/<id>/` (weights, α/γ, auction, intent schema, DMN
  rules, rails, fulfilment proof), validated by `verticals/check.py` in CI. FR-01 is live and FR-02…FR-09 are declared.
  Going live adds rules, rail adapters and one fulfilment verifier. WASI plug-ins (ADR-016) can wrap packs later for
  third-party verticals.
- **Rules:** **embedded DMN**. The pack's `.dmn` files are evaluated in-process (Fluxnova's Apache-2.0 DMN engine),
  compiled once per version and cached, with no network call in the 50 ms window. Fluxnova stays the authoring,
  versioning and approval UI.
  - **Engine** (verified 2026-11-19): `org.finos.fluxnova.bpm.dmn:fluxnova-engine-dmn:3.1.1`, with BOM `fluxnova-engine-dmn-bom:3.1.1`. Apache-2.0, usable standalone without the BPMN engine; packages `org.finos.fluxnova.bpm.dmn.engine.*`. Wrapped by `services/core/exchange-rules` (`PackRules`): each pack's `rules/*.dmn` are compiled once and evaluated in-process.
- **UI split by audience:** Exchange OME, audit and compliance become back-office micro-frontends (Rsbuild shell,
  Keycloak SSO). ShopBot (buyer) and Buying Partner become installable PWAs built from the prototype's React code, with
  the simulation replaced by real APIs, and later embedded in the Tauri edge app.
- **Hot path:** `BidBook` is struct-of-arrays and allocates nothing (PRD NFR-02: < 100 µs per bid, < 5 ms p99 match).
  Aeron Cluster (ADR-018) wraps it for replication.
- **Vendor-hosted pieces of the prototype** (serverless functions, edge KV, card-network SDK bridge) map to ports and
  open-source simulators (ADR-018). No vendor SDK sits in the core path.

## ADR-021 — Lighter alternatives to PDF components (owner-approved 2026-11-20)
Owner rule: the stack PDF is a reference; before installing a PDF component, check for a lighter or better current free
alternative and ask. Decisions from that review:

| PDF component | Chosen | Why | Footprint (measured) |
|---|---|---|---|
| DataHub (+ OpenSearch) | **OpenLineage + Marquez 0.50** | Cross-system lineage and impact analysis without OpenSearch/GMS; emitters: Trino event listener, `dbt-ol`, Flink 2 job-status listener. Owners/PII tags live in dbt meta, Apicurio labels, Polaris table properties. | Marquez ~250 MiB vs DataHub est. 3–5 GB |
| Trino + StarRocks | **Trino only** | Both queried the same Iceberg tables; StarRocks needed ~2.5 GB requested and caused most lakehouse install failures. qry-svc analytics query runs on Trino. | −2.5 GB requests |
| Weaviate | **pgvector** on the shared Postgres (database `ml`) | No extra stateful service; SQL joins with our data. | no new pod |
| Feast | **Feast, minimal** (0.67: registry SQL, online Valkey, offline Iceberg via Trino) | Point-in-time-correct training data for the fraud model. 0.47 failed the Trivy gate (two RCE CVEs). | Feast ~150 MiB |

Also: third-party tools with their own schema migrations run on the shared Postgres, not YugabyteDB (Temporal,
RisingWave, Harbor, MLflow and Polaris all broke on YugabyteDB DDL); YugabyteDB keeps DIFME's own data.


## ADR-022 — Payment-rail simulators from open-source systems (owner-approved 2026-11-21)
Owner request: connect DIFME to real payment systems by copying open-source projects onto our infrastructure. Each one
is vendored as pinned source in `vendor/` (`ci/vendor-sync.sh`, `vendor/VENDORED.json`) and built from there.

| Role | Chosen | Licence | Why / instead of |
|---|---|---|---|
| PSP (payment aggregator / gateway) for merchants and agents | **Juspay Hyperswitch** v1.129.0, test processor | Apache-2.0 | As requested. Its test processor's base URL points at DIFME's acquirer, so card payments reach the scheme (no change to Hyperswitch). |
| Core banking (CBS) | **Apache Fineract** 1.16.1 | Apache-2.0 | As requested. Escrow, merchant, partner and buyer accounts; transfers idempotent by `Idempotency-Key`. |
| Payment hub | **Mifos Payment Hub EE on Fluxnova** (vendored, MPL-2.0) | MPL-2.0 | Owner choice: keep Mifos's connectors and BPMN flows, replace only Zeebe (Camunda License 1.0, not OSI) with Fluxnova. Interim: `services/core/payment-hub` on Temporal until the port passes the end-to-end tests. |
| Settlement leg (central switch) | **Mojaloop Testing Toolkit** in hub mode + **mojaloop-simulator** with the SDK scheme adapter as the other bank; DIFME joins through PH-EE's Mojaloop connector | Apache-2.0 / MPL-2.0 | Owner choice (2026-11-21) over the full switch core (central-ledger etc., MySQL + Kafka). Routing rules generated from `deploy/platform/rails/mojaloop-switch/participants.json`. |
| ISO 8583 + card network | **moov-io/iso8583** v0.26.4 in `services/scheme-sim` (scheme + issuers, ISO adapter, acquirer) | Apache-2.0 | Owner choice over jPOS (AGPL-3.0): a small Go library and a lighter service. |

Flow: exchange → payment hub → Hyperswitch → acquirer → ISO 8583 → scheme/issuer; money is booked in Fineract (card
settlement to merchants, escrow hold/release/refund). Test cards only. Profile `rails`; the exchange uses these rails
when the profile's `exchange-rails` ConfigMap is present, otherwise its in-process simulators.

## ADR-023 — Fraud scoring and FRM on Tazama, on DIFME's stack (owner 2026-11-22)
**Decision (owner):** "for fraud scoring and FRM, let's use tazama-lf … clone it to our repo and use our stack for
redundant components in tazama code so that our overall code is optimized."

**Vendored** (Apache-2.0, `ci/vendor-sync.sh tazama-<repo>`, pinned v4.0.x in `vendor/VENDORED.json`, `vendor/tazama/`):
frms-coe-lib, frms-coe-startup-lib, tms-service, event-director, rule-executer, rule-901, rule-902, typology-processor,
event-adjudicator, admin-service, auth-lib, auth-lib-provider-keycloak. tms-service, event-director, typology-processor
and event-adjudicator ship no LICENSE file but declare Apache-2.0 in package.json and every SPDX header; the text is
added from `vendor/licenses/Apache-2.0.txt`. The `@tazama-lf/*` libraries are published only on GitHub's npm registry
(token required), so they are built from the vendored source.

**Pipeline:** TMS (ISO 20022 pain.001/pain.013/pacs.008/pacs.002 in) → event director → rule processors (rule-executer +
rule libraries) → typology processor → event adjudicator (alert / interdiction out). Configuration via admin-service.

**Redundant Tazama infrastructure → DIFME component:**

| Tazama | DIFME | Where the change lives |
|---|---|---|
| NATS (transaction plane) | Kafka 4 on Strimzi | a `KafkaService` implementing `IStartupService` in frms-coe-startup-lib (subject → topic, queue group → consumer group, same protobuf payloads) |
| Own PostgreSQL 18 | shared platform Postgres (ADR-019), one database per Tazama store | configuration only |
| Own Valkey | shared Valkey (cache-tier) | configuration only |
| Own Keycloak 23 | DIFME Keycloak (realm client for admin-service / TMS) | auth-lib-provider-keycloak configuration |
| Elastic APM (`elastic-apm-node` in frms-coe-lib) | OpenTelemetry → Alloy → Tempo / VictoriaMetrics | the APM wrapper in frms-coe-lib |
| ELK / lumberjack / event-sidecar logging | JSON stdout → Alloy → Loki | logger configuration |
| Hasura, pgAdmin, nats-utilities | not deployed | — |

**DIFME integration:** the payment hub and the exchange send pacs.008 before moving money and pacs.002 after; Tazama's
result (correlated by message id) gates the payment (timeout and fail-open/closed are flags). DIFME's ONNX fraud
model (`ml/fraud`, `services/fraud-scorer`) becomes a Tazama rule processor rather than a parallel scoring path, so
one engine combines it with the typologies. Hyperswitch is built without its `frm` feature (no separate FRM there).

**Not public upstream:** only rules 901 and 902 are open source; DIFME's own rules (the §7.4 business rules, the ONNX
score) are written as rule processors in the same shape.

**Licence scan (2026-11-22, ADR-001/ADR-009, owner: "only free and open source"):** all 1,134 npm packages in the 12
lockfiles. MIT 933, Apache-2.0 62, ISC 53, BSD-3 47, BlueOak-1.0.0 13 (OSI), BSD-2 12, CC0/Unlicense/0BSD, Python-2.0
(`argparse`), WTFPL-or-ISC. The three runtime packages with no lockfile licence (`json-bignum`, `busboy`,
`streamsearch`) are MIT per their registry metadata. `caniuse-lite` (CC-BY-4.0, browser-support data) is a test/build-
time dependency only and never ships in an image. Kafka client for the NATS replacement: `@confluentinc/kafka-javascript`
(MIT; librdkafka BSD-2), maintained; `kafkajs` (MIT) has been unmaintained since 2023.

**Hyperswitch FRM → Tazama (owner 2026-11-22: "make sure any rules from hyperswitch frm needs migrating"):** checked in
v1.129.0. Hyperswitch holds **no fraud rules of its own**: its `frm` feature only forwards payments to external paid FRM
services (Signifyd, Riskified, Cybersource Decision Manager, Sanlam Payshield, nSure; all excluded by ADR-001), and DIFME
never configured `frm_configs`. Nothing to port as rules. The behaviours it offers are carried over as requirements of
the Tazama integration in the payment hub:

| Hyperswitch FRM behaviour | In DIFME on Tazama |
|---|---|
| Pre-auth check (`FrmPreferredFlowTypes::Pre`): verdict before the charge | pacs.008 to TMS before the PSP charge; wait for the adjudicator's result (timeout, fail-open/closed flag) |
| Post-auth check (`Post`): verdict after authorisation, before capture | pacs.002 after the PSP's authorisation; an alert before capture triggers the action below |
| Actions `CancelTxn` / `AutoRefund` / `ManualReview` | per-typology action in the hub: cancel before capture, refund through the hub's existing refund saga, or hold for review in the back-office compliance app |
| Lifecycle events (checkout, transaction, fulfillment, record-return, payout) | sent to TMS as their ISO 20022 equivalents so rules see the history (returns and refunds included) |
| Card blocklist (`/blocklist`, not part of `frm`) | stays in Hyperswitch (built with `olap`) |

## ADR-024 — Card vault, network tokens and issuer card management (owner 2026-11-22)
**Why:** today only the PSP side tokenizes, and with Hyperswitch's built-in stand-in vault (`mock_locker = true`: card
numbers in Hyperswitch's own database). There are no network tokens and no issuer-side card management; the scheme
simulator's card ledger stands in for the issuer. jCard is excluded (source-available, not open source); no mature
open-source card-issuing system exists, so the issuer side is built on DIFME's stack. Order: after Tazama (ADR-023).

**1. Card vault — vendored `juspay/hyperswitch-card-vault` ("Tartarus", Apache-2.0, Rust, v0.9.0).**
Hyperswitch's `[locker]` points at it (`mock_locker = false`). Storage on the shared Postgres (database `locker`);
master and custodian keys and the Hyperswitch↔vault JWE/JWS key pairs in OpenBao (KV + agent injector, as for
Hyperswitch). Rails namespace, mesh mTLS, only the Hyperswitch router may call it. A second instance (own database and
keys) serves as the issuer's card-number vault for part 3.

**2. Network tokens — a token service (TSP) in `services/scheme-sim`.**
- Implements Hyperswitch's own `network_tokenization_service` contract (generate, fetch, delete, status, eligibility,
  alt-ID; JWE-encrypted payloads, API key), so Hyperswitch needs no code change: config only.
- Token vault at the scheme: token ↔ card number, token requestor (merchant/PSP), domain restrictions, status
  (active/suspended/deleted), expiry. Token ranges by BIN; the token number passes the Luhn check.
- Per-payment cryptogram: HMAC over token, amount, currency and a transaction counter with a per-token key; single use.
- On a 0100/0200 whose DE 2 is a token: check status, domain and cryptogram (failures answer with the scheme's
  decline codes), swap in the card number, route to the issuer, swap the token back in the response. Reversals and
  refunds work on the token as well.
- Lifecycle from the issuer (card replaced, blocked) updates or suspends its tokens.

**3. Issuer card management — new service on DIFME's stack (`services/core/card-issuer`, Quarkus like the core).**
- Card products (BIN range, credit/debit, limits, validity, fees placeholder), cards linked to a Fineract account.
- Issuance: card number generated in the product's BIN range with a Luhn check digit, stored in the issuer vault
  (the service keeps only the vault token and the masked number), expiry, CVV held as a keyed hash.
- Lifecycle: activate, block/unblock, report lost/stolen (replacement card, tokens moved or suspended), expire, close.
- Limits and controls: per-transaction, daily, per channel and merchant category.
- Authorisation: the scheme simulator's issuer leg calls the service, which checks card status and limits and places
  the hold in Fineract (available balance for debit, credit limit for credit), with Fineract releasing or settling it
  on reversal and clearing. The scheme's in-memory card ledger is retired.
- Back-office: card screens in the compliance/settlements apps; Keycloak roles.
- Moves onto jPOS (AGPL-3.0) when the switch migrates there (owner 2026-11-22).

**End-to-end flow:** cardholder account (Fineract) → card issued (number in the issuer vault) → network token for the
merchant (TSP) → token stored in Hyperswitch's vault → each payment carries the token and a cryptogram → scheme
swaps it for the card number → issuer authorises against Fineract → Tazama (ADR-023) sees each step.

**References studied for ADR-024 (2026-11-22; reading only, nothing vendored yet):**

| Repository | Licence | What we take from it |
|---|---|---|
| [srosio/card-engine](https://github.com/srosio/card-engine) | Apache-2.0 | Closest match to part 3: card orchestration over an existing core (has a Fineract adapter). Authorisation = card state → rules (per-transaction and daily limits, MCC blocking, velocity) → reserve funds → record → respond, idempotent by key; clearing and reversal services. Small (~5.6k lines, 6 tests, MVP mocks), so a design reference, not a dependency. It keeps holds in its own table and settles with a Fineract withdrawal; DIFME uses Fineract's native `holdAmount` / `releaseAmount` savings commands instead (present in the vendored 1.16.1), so the hold lives in the bank's ledger. |
| [jpos/jPOS-EE](https://github.com/jpos/jPOS-EE) | AGPL-3.0 | For the later jPOS migration: `cryptoservice` / `cryptoserver` (AES-256 card-number encryption, keys protected with PGP), `minigl` (general ledger), `saf` (store and forward), `cmf` (jPOS common message format), `txn` (transaction manager), client/server simulators. |
| [cloud-itonami/cloud-itonami-card-issuing](https://github.com/cloud-itonami/cloud-itonami-card-issuing) | AGPL-3.0 | Issuer-side scope checklist only (BIN sponsorship, cardholder provisioning, authorisation policy, lifecycle, disputes); a governance blueprint, no processing code. |
| BIAN service domains *Issued Device Administration*, *Card Authorization*, *Card Transaction Switch* | open specification | Vocabulary and boundaries for the card-issuer service's API. |

Not used: `sebastianrm/cards-service` has no licence (all rights reserved), so it isn't read for code.

## ADR-025 — Lending: Fineract as LMS, loan origination on DIFME's process stack (owner 2026-11-22)
**Survey (2026-11-22; licence files, size, activity and code checked, not READMEs):**

| System | Licence | Finding | Use |
|---|---|---|---|
| Apache Fineract 1.16.1 / Mifos X (already vendored) | Apache-2.0 | Full LMS: products, schedules, interest, accounting, delinquency buckets and actions, re-age/re-amortise, charge-off, chargebacks, application → approve → disburse lifecycle. No revolving line or card statements; `fineract-loan-origination` only records loan originators; the working-capital loan is a discount-fee, breach-based merchant product. | **The LMS** |
| [frappe/lending](https://github.com/frappe/lending) | GPL-3.0 | The most complete open-source LOS + LMS found (active; 80 data types): loan applications, line of credit with revolving limits, collections and dunning, RBI IRAC classification and provisioning, co-lending, loans against securities. Requires ERPNext + Frappe (Python, MariaDB-first, own workers and general ledger). | **Functional reference only**: a second stack and a second ledger next to Fineract; GPL code is read for design, never copied |
| [fireflysoftwaresolutions/core-lending-credit-cards](https://github.com/fireflysoftwaresolutions/core-lending-credit-cards) | Apache-2.0 | Revolving line → billing cycle → statement → transactions → payments; ~1.2k lines of CRUD services, no interest, statement or minimum-due computation, 1 test. | **Data-model reference** for the card-credit entities |
| Small GitHub "loan management system" apps | none / proprietary | Demo-level | Not used |

**Decision:**
- **LMS = Fineract (Mifos X engine).** Debit and prepaid cards on savings accounts with native `holdAmount` / `releaseAmount`.
  Credit cards on a multi-disbursement loan with a maximum outstanding balance (each clearing = a disbursement,
  repayments free the limit), Fineract keeping balance, interest, accounting, delinquency, collections and chargebacks.
- **Card-credit logic in `services/core/card-issuer` (ADR-024):** available credit = limit − outstanding − open
  authorisations (authorisation holds tracked by the issuer: Fineract has no hold on loans), billing cycle and statement
  job (statement balance, minimum due, due date), interest-free grace when paid in full (interest waived in Fineract),
  renewal of the loan before maturity so the line is open-ended. Built and tested by DIFME; Firefly's schema as the
  starting model.
- **Gate before building credit:** a live test against Fineract of the full cycle — spend, repay, re-spend within the
  limit, interest, a late payment moving into a delinquency bucket, a chargeback. If the loan model does not hold, the
  revolving module lives in card-issuer and Fineract keeps only the accounting entries.
- **Gate result (2026-11-22, `ci/fineract-credit-gate.sh`, Fineract 1.16-line image):** spend → repay → re-spend
  works on a multi-disbursement loan, and Fineract's principal outstanding follows actual repayments. **The native
  `maxOutstandingLoanBalance` is not a revolving limit:** it is checked against the *scheduled* balance (repayments not
  counted: after spend 3000 / repay 2000, a 2500 spend is refused at limit 5000) and not at all for a second tranche on
  the schedule's first day. So the limit is **enforced by card-issuer** (open-to-buy = limit − Fineract principal
  outstanding − open holds; the gate's part 2 passes: re-spend to exactly the limit, over-limit refused, cleared to 0),
  loans carry no `maxOutstandingLoanBalance`, and the approved principal is a large lifetime ceiling renewed by
  card-issuer. Fineract also caps tranches per loan (`maxTrancheCount`), so card-issuer books clearings to Fineract as
  one disbursement per day (or per statement cycle), not per purchase. **Gate complete (2026-11-22, night):** part 3
  of the same script passes too: interest charged (24% a year), an unpaid instalment classified in delinquency bucket
  D1 (1–30 days), and a chargeback of a repayment putting the amount back on the line. card-issuer
  (`services/card-issuer`) implements the credit card on this basis (`ci/card-issuer-live.sh`).
- **Built (2026-11-22, night):** loan origination = `processes/bpmn/loan-origination.bpmn` + `processes/dmn/credit-decision.dmn`
  + `forms/loan-application.json`/`loan-review.json`; Temporal `LoanScreeningWorkflow` (Tazama pain.001, typology
  difme-3ds-risk) and `LoanBookingWorkflow` (Fineract loan, approval, disbursement, idempotent on the business key) in
  saga-orchestrator; Keycloak client / Fineract user `loan-origination`, product "DIFME term loan". Tests: engine
  (decision table, approve / refer→underwriting / decline paths), Temporal, live Fineract booking. Credit cards:
  card-issuer statements (cycle, minimum due 5% ≥ INR 100, due +20 days, interest-free grace by waiving interest in
  Fineract, daily billing run).
- **LOS on the existing process stack (ADR-008):** Form.io application forms; Fluxnova BPMN for KYC → appraisal →
  approval → disbursement; DMN for credit-decision rules; Tazama (ADR-023) for fraud screening; Fineract holds the
  application, approval and disbursement records. Frappe Lending is the checklist for steps and Indian regulatory
  features (IRAC classification and provisioning, co-lending, collections and dunning).
- **Order:** debit/prepaid cards first; credit after the gate above. The Mifos web app is not deployed (DIFME's
  back office covers it); it can be added later if wanted.

## ADR-026 — Payment security module and attested key release (owner 2026-11-22)
**Security module:** a DIFME `hsm` service wrapping jPOS's `JCESecurityModule` (AGPL-3.0; matches the planned jPOS
migration), reached only through jPOS's `SMAdapter` interface so a certified payment HSM (Thales payShield, Futurex,
Utimaco, a cloud payment HSM) replaces it later without caller changes. Checked in source (jPOS, 2026-11-18): it
implements ARQC verification / ARPC generation with EMV key derivation, secure-messaging session keys and MACs for
issuer scripts (incl. PIN change), CVV / CVV2 (CVD) / iCVV / dCVV / CVC3, CAVV, PIN translation and PVV, MACs, key
generation/import/export with check values, SDA/DDA/CDA. It exposes only those functions (no clear-key export), over
the mesh with mTLS. Every function is cross-checked in tests against **pyemv** and **psec** (MIT) and published test
vectors. Order: CVV2 and CAVV (network-token cryptogram) first, for today's card-not-present payments; PIN, chip
ARQC/ARPC and issuer scripts with card-present flows. This replaces two ADR-024 shortcuts: CVV as a keyed hash in
OpenBao and an HMAC token cryptogram become the standard algorithms in the security module.
**Progress (2026-11-22):** `services/hsm` — `SecurityModule` over jPOS 3.0.2's `SMAdapter` / `JCESecurityModule`:
CVK from clear components (key ceremony, returned only under the LMK), CVV2, magstripe CVV, Visa CAVV, with verify.
10 tests pass, matching the published Visa CVV vector (561) and psec 1.x for every value; reloads from the same LMK file.
pyemv 1.5 has no CVV function, so psec is the CVV/CAVV reference (pyemv stays the reference for ARQC/ARPC).
Next: the mTLS service around it, LMK from the attested key release, then card-issuer and scheme-sim calling it
(replacing the keyed-hash CVV and the HMAC token cryptogram), then PIN/PVV and ARQC/ARPC.
**Progress (2026-11-22, later):** 37 tests in `services/hsm`, every value checked against an independent
reference. Built: key ceremony/generation/KCV, ZMK exchange, TR-31 versions B and D (psec interop), AES KBPK;
CVV2/CVV/CAVV, DIFME dCVV2 profile; Visa PVV, IBM 3624 offset, ZPK translation, DUKPT TDES (X9.24 vector), ISO 9564
format 4 ↔ 0 (psec); ARQC/ARPC for Visa CVN 10/18/22 and Mastercard CVN 16/17/20/21 (pyemv); dCVV, CVC3; issuer
script MACs and the offline PIN change script byte-exact (pyemv); retail MAC (psec), AES-CMAC (NIST); EMV
personalisation certificates (verified by jPOS's Book 2 recovery). Service: labelled key store and HTTP endpoints;
image `difme-hsm`; rails app `card-security` (hsm + ACS, AuthorizationPolicy: ACS and scheme-sim only). scheme-sim's
network tokens now carry a TAVV from the hsm. Open: AES DUKPT and AES chip cryptograms (no open reference vectors
found), Mastercard AAV/SPA2 and Amex AEVV (scheme specifications not public), PIN generation/weak-PIN list, LMK
rotation drill, callers in card-issuer (not built yet).
Full scope (all card cryptography: key management, CNP, PIN, chip, issuer scripts, personalisation, terminals),
with the reference test and caller for each function and jPOS's gaps (no AES, IBM 3624 offset, TR-31, RSA signing):
[card-cryptography-plan.md](card-cryptography-plan.md).

**Progress (2026-11-23):** 64 tests in `services/hsm`, plus card-issuer callers; every value is checked against an
independent reference, with negative cases.

- **MAC verify.** `/v1/mac/retail/verify` (ISO 9797-1 alg 3) and `/v1/mac/cmac/verify` compare the MAC in the module
  in constant time (`MessageDigest.isEqual`, truncated MACs allowed). References: psec/pyemv retail MAC, NIST
  SP 800-38B.
- **App PIN reveal.** `/v1/pin/reveal` returns the PIN only as a JWE to the app's key: RSA-OAEP-256 or ECDH-ES (P-256),
  with A256GCM. Reference: jwcrypto decrypts it, and refuses another key and a tampered token. card-issuer
  `POST /v1/cards/{id}/pin/reveal` reveals once, keeping a generated PIN as an opaque ISO 4 block until then. It is
  audited and limited to 5 attempts per card per hour.
- **TC/AAC at clearing.** card-issuer parses field 55 of a presentment (Visa CVN 10/18/22, Mastercard CVN 16/17/20/21)
  and verifies the cryptogram with `/v1/arqc/verify`. An AAC, or a cryptogram that does not verify, is not posted: the
  authorisation stays held and is marked. Reference: pyemv TC/AAC vectors.
- **Renewal and reissue** in card-issuer:
  - same or new PAN by product setting, and always a new PAN for lost/stolen;
  - CVV2 from the module, the vault updated;
  - the old card or old expiry stays valid until the new card's first use or the grace date;
  - verified live through ISO adapter → scheme-sim → card-issuer (Postgres vault).
- **LMK rotation.** jPOS's software module declares `translateKeyFromOldLMK` but does not implement it; DIFME now
  implements it. `KeyRelease` rotates generation n-1 into n (`difme/hsm/lmk-gn`…). The new LMK/KBPK are created in
  the module and stored only through the create-only `hsm-bootstrap` role. Test: every key family gives the same
  psec/pyemv/NIST results after rotation. Runbook: `docs/knowledge-base/ops-hsm-lmk-rotation.md`.
- **Issuer RSA key and perso file.**
  - The issuer RSA key exists only as a TR-31 block under the KBPK (bootstrap `issuer-rsa=RSA-EMV/1408`).
  - The DIFME-PERSO/1 bureau file (`PersoFile`, `/v1/perso/batch`, card-issuer `POST /v1/perso`) holds the ICC
    master keys and the ICC RSA key as TR-31 B blocks under the bureau KEK, the ICC certificate signed in the module,
    and the iCVV.
  - Round trip: pyemv option A keys, psec TR-31 unwrap, psec iCVV, jPOS Book 2 recovery.

**Blocked** (no public specification or reference vectors): Mastercard AAV/SPA2, Amex AEVV and AES chip cryptograms
(beyond pyemv's TDES CVN 22).

**Still open:**

- the KBS/OpenBao round trip of the rotation (first cluster drill);
- chip ATC replay tracking at clearing;
- scheme-sim sending field 55 at clearing;
- the app moving from `appPinBlock` to the reveal endpoint, after which `appPinBlock` is removed from
  `/v1/cards/{id}/pin/generate` (still used by `ci/card-issuer-live.sh`).

**Keys only in the (emulated) TEE — enforced on the cluster (2026-11-22, later):** the security module has its own
KBS client (`KbsClient`: protocol 0.4.0, sample TEE evidence with report data = SHA-384 of the RFC 8785 runtime data,
RSA-OAEP-256 + A256GCM JWE) and starts only through `KeyRelease`: attest, fetch `difme/hsm/{lmk,kbpk,keys}` into
memory; on the very first start (resources absent, attestation affirming) generate them inside the module and store
them through OpenBao role `hsm-bootstrap` (create only). It refuses to start without HSM_KBS_URL (dev switches need
HSM_DEV_INSECURE=true and exist only for local tests). The ACS holds no keys (PS256 signing and HMAC are hsm calls).
Cluster: Trustee (KBS + AS + RVPS) as app `tee-key-release` in `security`, reading OpenBao mount `kbs` with role
`trustee-kbs` (read only), admin API only over the pod loopback, mesh access only for `rails/hsm`; no keys in
Kubernetes Secrets (`dev-secrets.sh` holds none; `ci/no-key-material.sh` in verify fails on key material in
`deploy/`). Verified against real Trustee (`ci/hsm-key-release-test.sh`): first start generates and stores; restart
gets the same keys by attestation; a changed measurement and a missing KBS both prevent start-up.

**Keys never in clear outside the module — attested key release (verified hands-on 2026-11-22):**
- The master key (LMK) lives in **OpenBao**; working keys exist only encrypted under it.
- **Trustee** (Confidential Containers; Apache-2.0) releases the LMK: its key broker reads OpenBao through its
  `vault_kv` backend with a read-only token (`kbs/difme/*`) and returns it as **JWE encrypted to the public key the
  TEE put in its attestation evidence**, so a stolen token alone gets nothing. Release only when the attestation
  result (an EAR token) is **affirming** (`resource-policy.rego`).
- The module runs in a TEE. Production: Confidential Containers on AMD SEV-SNP or Intel TDX nodes, appraised by
  Trustee's own verifiers with upstream's policy (a software TEE is never affirming there). Development: Trustee's
  emulated "sample" TEE with `attestation-policy.dev.rego`, where the sample `svn` stands in for the module's code
  measurement (`difme_hsm_measurement` reference value).
- **Verified** (`ci/tee-key-release-test.sh`, Trustee images kbs-grpc-as@sha256:c24e5fda…, coco-as-grpc@sha256:b0b86ba6…,
  rvps@sha256:16410d79…; OpenBao 2.7 dev server): no registered measurement → contraindicated, **refused** (403
  PolicyDeny); measurement registered → affirming → **released**, equal to the value in OpenBao; measurement changed
  (a modified build) → **refused**.
- Findings for production: Trustee's `vault_kv` backend defaults to `verify_ssl = false` (set it true, with DIFME's
  CA); sample reference values are stored as strings (`["1"]`), so policies compare strings; upstream's default policy
  can never affirm the sample TEE (no launch digest), which is right for production.
- **Emulation gives no protection**: in an emulated TEE the host's root can still read memory. It proves the design
  (attestation-gated, JWE-bound release, no key on disk or in operators' hands) so real hardware is a deployment
  change. The free hosts in use (GitHub runners, the free arm64 VM) have no TEE hardware; until confidential nodes or a
  certified HSM are used, keys are protected by design, not by hardware. Also in place regardless: LMK split into
  custodian components (dual control), memory locked and core dumps off in the module.
- **Considered:** OpenBao JWT login on Veraison's signed results (works, but hands the secret to any holder of the
  token; Veraison stays for device/edge attestation, §11.1); Arm CCA realms under QEMU (FEAT_RME is experimental in
  QEMU and needs the full firmware stack: not viable on a 4-core VM); SoftHSM2 (BSD; derives keys inside the token,
  but has no payment functions).

**ADR-023 progress (2026-11-22):**
- Built from source, all test suites green (libraries and services), every package's `@tazama-lf` dependency from
  `vendor/tazama` (`ci/tazama-local-deps.py`). Upstream bugs found and patched: `tslib` missing from frms-coe-lib's
  runtime dependencies; rule-executer's rule alias only resolvable with npm's install-links.
- Kafka transport verified against a real Kafka 4.1 broker (load sharing, exactly-once handling per transaction in the
  test, broadcast, runtime subscribe); OpenTelemetry swap verified for trace continuation.
- **End to end** (`ci/tazama-e2e.sh`, Docker): TMS → event director → rules 901/902 → typology processor →
  adjudicator over Kafka, schema via `deploy/platform/fraud/tazama/schema.sh` on databases `tazama_*`, the committed env
  files: a pacs.008 + pacs.002 ends as an **ALRT** evaluation (901 `.01` + 902 `.01` = 200 = alert threshold).
- Cluster manifests: profile `fraud` (`deploy/platform/fraud/tazama`); role and databases from the shared Postgres's
  init (`96-tazama.sh`, secret `tazama-db`). `NODE_ENV=dev`: in Tazama it only decides whether Redis needs a password,
  and DIFME's Valkey is reached over the mesh without one. Not yet run on a cluster; admin-service image built but not
  deployed (configuration is loaded by the schema job for now).
- Next: DIFME rules (the ONNX fraud score as a rule processor, the §7.4 business rules), the payment-hub hooks (checks
  before the charge and before capture; cancel / refund / review actions), cluster run.
- **2026-11-22, rule D01 and the full pipeline verified:** DIFME's ONNX fraud model runs as Tazama rule D01
  (`services/fraud-rules/rule-d01`, 13 tests, run in every image build): probability ×1000 banded like the scorer's
  own decision (ALLOW / REVIEW / BLOCK); a scorer that doesn't answer within 300 ms gives `.err` (no weight).
  `ci/tazama-e2e.sh` (seven images, a stand-in scorer at 0.7): **ALRT**, typology scores 901+902 = 200 and the
  fraud-model typology = 400 (interdiction threshold). Found on the way and fixed: consumers subscribing before their
  topic existed missed messages (transport now waits for topic metadata, refresh 10 s); the e2e script left containers
  behind. Images: 7 of 8 pushed and signed after moving the run stage to Debian slim with security updates (Trivy
  blocked a CRITICAL libssl3 in the distroless base); rule-d01 rebuilds after a test-timing fix.
- **2026-11-22, payment hub on Tazama (the FRM replacement):** with `TAZAMA_TMS_URL` / `TAZAMA_ADMIN_URL` set, the hub
  authorises card payments only, reports them to Tazama (pacs.008 + pacs.002, the payer as DIFME's account id, never
  the card) and reads the evaluation from Tazama's admin service (`/v1/admin/reports/getreportbymsgid`, now deployed):
  no alert → capture and settle; alert → status REVIEW (`POST /v1/card-payments/{id}/review` approves or rejects);
  a typology at its interdiction threshold → the authorisation is cancelled, DECLINED FRAUD; no verdict within
  `TAZAMA_BUDGET_MS` (3 s) → REVIEW, or capture with `TAZAMA_FAIL_OPEN=true`. These are Hyperswitch FRM's
  CancelTxn / ManualReview actions; AutoRefund isn't needed because the check runs before capture. Tests: 23 (fake
  Hyperswitch and Tazama on real HTTP, settlement in Temporal's test environment); `TazamaLiveTest` checks the client
  against a real Tazama: run against `ci/tazama-e2e.sh`'s stack (2026-11-22), TMS accepted the hub's messages and the
  hub read the real report as **INTERDICT** (901+902 = 200, fraud model = 400), so it would cancel the authorisation.
- **ADR-024 progress (2026-11-22): network tokens built** in `services/scheme-sim` (`internal/tokens`): tokens in their
  own range (489537…, Luhn-valid) bound to a requestor; single-use cryptograms (HMAC over token, requestor, amount,
  counter; per-token key in the TSP) carried in ISO 8583 field 48; on 0100/0200 the network checks status, requestor
  (field 42), cryptogram and counter, swaps in the card number for the issuer and keeps the token in the response
  (decline codes: unknown 14, suspended/other requestor 62, cryptogram missing/wrong/replayed 05); lifecycle
  suspend/resume/delete and card replacement. Admin API: `POST /v1/tokens`, `POST /v1/tokens/{t}/cryptogram`,
  `PUT /v1/tokens/{t}/status`. Tests: approve-and-hold, every decline, lifecycle (race detector). Remaining for ADR-024:
  Hyperswitch's network-tokenization contract (JWE) in front of this API, the card vault, the card-issuer service.
- **2026-11-22, §7.4 business rules on Tazama:** L1 "amount z-score > 3" is rule **D02**
  (`services/fraud-rules/rule-d02`, 9 tests): z-score x100 of this amount against the debtor's earlier pacs.008 in
  Tazama's event history (90 days, ≥ 5 payments; otherwise `.x01`, no weight), banded at 2 and 3 standard deviations,
  added to the fraud-model typology (.02 → 100, .03 → 200). L1 velocity = public rule 901; new device, geo jump and
  weak edge attestation are not in ISO 20022 payment messages and reach Tazama through the ONNX model (rule D01).
  Not yet re-run end to end (`ci/tazama-e2e.sh` now includes D02; a first-time debtor gives `.x01`, so its expected
  scores are unchanged).

## ADR-027 — Lightweight 3-D Secure ACS (owner 2026-11-22)
**Survey (2026-11-22, GitHub search + web):** there is no maintained open-source EMV 3DS 2.x ACS. What exists:
EMVCo-approved ACSs named "Open ACS" (Seglan) and "open-acs" (PAYSYS Labs) are products without public code;
`rbkmoney/three-ds-server` (Apache-2.0, last push 2023) is the merchant-side 3DS Server, not an ACS, but its domain
library is a usable reference for message models; `copyleftdev/emv-3ds` (MIT, small) models AReq/ARes/CReq/CRes;
`iicuriosity/3DS_Server` (MIT) is again a 3DS Server; `cnpshield/3dslab` has no clear licence (not used). Commercial
ACSs (Netcetera, Entersekt, …) are out (owner rule: free and open source only). **Decision:** build a small DIFME
ACS, using those projects and the EMV 3DS 2.2 specification as references only (no code copied).

**Design (`services/scheme-sim/internal/acs`, binary `cmd/acs`; the shared CAVV code is `internal/threeds`):**
- **AReq → ARes:** card from card management (scheme-sim's card API today, card-issuer when it exists): unknown →
  N/08, blocked or restricted → N/12, expired or wrong expiry → N/05, CMS unreachable → U/09. Then FRM: Tazama
  through the same pacs.008 + pacs.002 + admin-report flow and verdict mapping as the payment hub (ADR-023), with an
  HMAC card reference, never the PAN. INTERDICT → R/11; NO_ALERT within the frictionless limit (default INR 5,000)
  and no mandated challenge → **Y frictionless** with a CAVV, ECI 05; otherwise → **C challenge**. Without FRM
  configured every authentication is challenged.
- **Challenge (CReq/CRes):** 6-digit one-time passcode (stored only as an HMAC), 5-minute lifetime, 3 attempts,
  cancel supported; outcome Y (CAVV, ECI 05) or N (01, 14, 19) sent to the directory server as an **RReq**.
- **CAVV:** 20 bytes, DIFME layout modelled on Visa's CVV-with-ATN method (documented in `internal/threeds/cavv.go`):
  result code, second-factor code, key indicator, CVV output **from services/hsm** (jPOS `calculateCAVV`), the ATN's
  last 4 digits as unpredictable number, ATN, ECI. It binds card, result codes and ATN; like Visa's it does not bind
  amount or merchant.
- **Authorisation switch:** CAVV travels in ISO 8583 field 48 (`CAVV:`; the ISO adapter's `cavv` field fills it).
  scheme-sim verifies it with services/hsm (format, ECI vs result code, key indicator, cryptogram), refuses a reused
  ATN (05), records ECI on the transaction; security module unreachable → 91.
- **Security module:** `services/hsm` gained its HTTP interface (`HsmServer`: `/v1/cavv`, `/v1/cavv/verify`,
  `/v1/cvv2/verify`; never returns keys; CVK provided encrypted under the LMK).

**Verified (2026-11-22):** Go tests under `-race` (ACS, CAVV layout, switch; the test stand-in reproduces the Visa
vector and psec values); `services/hsm` 13 tests; `ci/acs-e2e.sh` with all real processes — Java hsm, ACS, scheme-sim,
ISO adapter: challenge → OTP → RReq Y with CAVV → authorisation 00 verified by the hsm → same CAVV 05 (replay) →
forged CAVV 05. Tazama is exercised against a fake TMS/admin in the Go tests (the client mirrors the payment hub's,
verified live against Tazama); the live ACS-to-Tazama run comes with the cluster.

**EMV 3DS 2.3.1 alignment (2026-11-22):** message versions 2.3.1 (preferred) and 2.2.0; device channels 01 app,
02 browser, 03 3RI (non-payment only, frictionless on a clear FRM verdict, else N; payment 3RI → N/21); message
categories 01 PA and 02 NPA; acsRenderingType (native/HTML; templates text, single-select, OOB, HTML OOB).
Authentication methods: OTP text with resend; single-select (cardholder chooses SMS or email for the passcode);
out-of-band approval in the DIFME app (`POST /3ds/oob/{acsTransID}` from the app backend; CAVV second-factor 02);
decoupled authentication (transStatus D, acsDecConInd, RReq when approved/declined or at
threeDSRequestorDecMaxTime, reason 24). Browser: `POST /3ds/challenge` takes the base64url CReq + threeDSSessionData,
renders the challenge (html/template, CSP), and posts the final base64url CRes to the AReq's notificationURL. App:
ECDH-ES with the SDK's ephemeral P-256 key, ConcatKDF (PartyVInfo = SDK reference number), acsSignedContent JWS PS256
with x5c, CReq/CRes as `dir` JWE (A128CBC-HS256, A128GCM with per-direction halves); verified against an independent
SDK stand-in (jwcrypto + pyca/cryptography, `internal/acs/testdata/sdk.py`). Card management gained enrolled
`channels` (sms, email, app).

**WebAuthn / SPC (2026-11-23):** `internal/acs/fido.go`. Codes from public sources (EMVCo text is not
redistributable; each field's source is cited in the code): authenticationMethod 13 WebAuthn / 14 SPC (2.3.1; Ravelin
API reference, EMVCo "WebAuthn and SPC" article); authenticationType has no FIDO value (01–04 only), so 02 dynamic is
sent; acsInfoInd 06/07 (nsoftware 2.3.1 notes); transStatus S, threeDSReqAuthMethod 09, prior method 05 (EMVCo
article); threeDSReqAuthMethod 06/07 FIDO Authentication Data (FIDO Alliance technical note 2020); SPC client data
`payment.get` and its checks (W3C SPC §9.1). Flows: issuer-initiated, where the browser challenge page (acsUiType 05)
calls SPC or `navigator.credentials.get`, and the ACS checks challenge, origin, rpIdHash, UV, ES256/EdDSA/RS256
signature and the signature counter (compare-and-set), and for SPC the amount, currency, payee and instrument in
clientDataJSON; merchant-initiated, where ARes S carries webAuthnCredList + spcTransData and AReq #2 (method 09,
prior ref = acsTransID) is checked against AReq #1, after which the challenge is consumed. Both give Y with a CAVV
from the security module (second factor 03), ECI 05. An unknown credential, a browser decline or a card without a
credential falls back to OTP. Requestor 06/07 data is validated and logged as risk input only. The issuer app
registers credentials at
`/3ds/fido/registration/options` + `/3ds/fido/registration` (WebAuthn attestation verified, SPC payment extension;
optional `ACS_ISSUER_TOKEN` bearer, shared with `/3ds/oob`). Credentials store only id, COSE public key and counter,
filed under the HMAC card reference: in memory, or in Postgres `acs_fido_credential` sealed with the card-vault key.
Library: go-webauthn v0.18.2 (BSD-3); govulncheck shows no reachable third-party vulnerabilities (x/crypto bumped to
v0.59.0); the stdlib findings need the image built with Go ≥ 1.26.9. Unverified: the JSON keys inside spcTransData and
webAuthnCredList entries, and the encoding of the assertion in threeDSReqAuthData (WebAuthn JSON here). Not yet
tested in a real browser.
**Still open (updated 2026-11-23):** scheme-issued ACS signing certificate from OpenBao (ACS_SIGNING_CERT_CHAIN
takes the chain; the cluster still uses the module's own certificate); multi-select and information-only templates
are modelled, not used by policy; FIDO/SPC in a real browser and with a real 3DS Server; 3DS Method (device
fingerprint iframe) and browser data in risk; a 3DS Server for merchant-initiated flows; real app push (OOB is logged
in development). **Done since:** FIDO/WebAuthn and SPC (unit-tested with a software authenticator); DS simulator with
attempts CAVV stand-in; durable challenge store, sealed with the module's card-vault key; image and manifests;
passcode delivery by email and email-to-SMS (SMTPSender; Mailpit on the development cluster, the card's email/mobile
from card-issuer).
**Earlier "not yet" list (superseded where done above):** HTML browser challenge page and app-channel JWE (CReq/CRes are JSON today);
other challenge methods (app push / biometric via the DIFME app, out-of-band); 3RI and non-payment categories;
attempts CAVV by a scheme stand-in; directory-server simulator and a 3DS Server (Hyperswitch has 3DS connectors) for
merchant-initiated flows; persistence of pending challenges (in memory today: a restart loses open challenges);
OTP delivery through the notification service; container image and rails manifests. Known FRM caveat: the
authentication and the later payment are both reported to Tazama, so velocity rules count the purchase twice; fix
with a separate network map / transaction type for authentications.

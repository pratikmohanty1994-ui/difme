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

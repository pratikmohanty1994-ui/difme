# Owner rules, decisions and open questions

Imported from the agent sessions of 2026-11-17 to 2026-11-20 so that no answer lives only in a chat transcript.
Newest first within each section. When the owner answers a question, move it from **Open** to **Decided** with the date.

## Working rules (in force)
- **Optimisation order** (2026-11-20): memory first until it is as low as it goes, then CPU, then disk I/O, then network I/O bandwidth. Each stage is measured per process/thread (`ci/proc-report.sh`) and a change stays only if it beats the baseline.
- **Save progress after every step** (2026-11-20, "so that nothing is lost in abrupt stoppage of GitHub Actions or network issues"): push work to a `wip-*` branch as soon as it exists, and update the PROGRESS LOG in `docs/status.md` on `main` (branch, fix, run, next action) after each step.
- **Optimise for memory, always; keep as much free as possible** (2026-11-20). Every profile and component is sized from measurements, and a change stays only if it beats the recorded baseline (CONVENTIONS.md footprint rule).
- **Nothing runs on the owner's PC** (2026-11-20): no builds, installs, scans, watchers, `git` or `gh`. Work happens in a cloud agent session, GitHub Actions, or the runtime VM/Codespace.
- **Never sit idle.** While something runs in the background, work on the next items using what is known about the system.
- **Be proactive about delays.** Know how long a step should take, track how long it has taken, and report an overrun without being asked. Watchers get deadlines and fail fast.
- **Install profiles in order, one at a time:** observability → lakehouse → process → security → ml → backoffice → hub → platform-ops. After each: memory report, fix defects, then decide whether it stays up or runs on demand. (With cluster-verify, independent profile sets may run in parallel on separate runners; each run still installs its profiles in this order.)
- **Squeeze resources with world-class techniques:** memory, I/O and CPU first. Tuning the source of open-source tools is allowed. Apply shared-memory, multi-process and multi-threading best practice.
- **Commit before switching branches** (an uncommitted edit once leaked into another branch). Time each step of a long sequence.
- **No company or vendor references and no assistant attribution** in the repo, commits or PRs; no assistant-instruction files.
- **Security:** the owner's personal email stays private and never goes to outside services. Tokens never go into the repo, files, logs or chat. A token pasted in chat is treated as leaked: revoke and rotate it.
- **Open source with no limitations** (2026-11-17, "make sure everything we use should be open source and free to use with no limitations"): OSI-approved **and** no watermark/attribution-display terms, no BSL/SSPL/ELv2/source-available, no usage-capped free tiers or paid feature gates; copyleft is fine. This overrode the earlier bpmn-js watermark exception. State unavoidable platform quotas honestly (e.g. Codespaces hours).
- **When something fails or a better free option exists, offer the alternatives as a choice** and let the owner pick before adopting.
- **The stack PDF is a reference, not a spec** (2026-11-20, "the stack pdf was just a reference.. if better latest open source free alternatives available.. just ask me"). Before installing any PDF component, check whether a lighter or better current free OSS alternative exists; if so, ask the owner with the options (footprint, what each covers) instead of installing the PDF choice by default.
- **Everything is driven from the cloud** (2026-11-18, from the phone: "Can't the watcher not be in the remote server, so that I can control everything from this cloud session"). Watchers and long waits run remotely (Actions, runtime VM), never on the PC. Lockfile generation and licence scans go into a small `workflow_dispatch` job.
- **Parallel when safe; lightweight with maximum throughput** (named owner rules, see Footprint in CONVENTIONS.md).
- **Prava skills in every session** (2026-11-17, "make sure they are available in any future sessions also"): `prava-pay` and `prava-shopping` are installed globally by the Default cloud environment's setup script and on the PC.
- **Never modify or remove any file on the owner's PC without explicit permission** (2026-11-20, "a very important strong rule -> never ever modify/remove any files in local without my permission..keep this in memory for all your future sessions also"). Reading is allowed where the owner has said so (the Downloads folder documents, 2026-11-20); anything extracted from local documents is stored only remotely (cloud session scratchpad, repo or Actions), never written back to the PC.
- **Imported from the earlier PC sessions (2026-11-17 → 20; memory notes and session log uploaded 2026-11-20).** Rules not recorded elsewhere:
  - **Squeeze the tools themselves** (2026-11-18): "since you have the open source code access to all the tools you may choose to fine tune their code also such that memory and io and cpu usage is optimized". Prefer configuration first; patch upstream code only when config can't reach the target, and keep the patch vendored and documented.
  - **Concurrency without bloat** (2026-11-17/18): virtual threads, parallel operators, async/batched I/O; multiple processes/pods/slots; shared memory (off-heap/zero-copy buffers, memory-mapped files, process-shared caches, shared-memory IPC), "generic C++ multi processing rules as well as multi threading". No thread pools sized beyond the cores, no heavy per-thread caches.
  - **State the expected duration** of every long job (install, image build, load test) with a deadline of ~1.5×, watch for failure signals each poll, and report an overrun before the owner asks (2026-11-18: "you should know yourself how much is expected time and how much it's already taken"). Reference durations: cluster create ~2.5 min, base ~3–5 min, core ~3 min, streaming ~6 min, lakehouse ~2–4 min, image build ~25–30 min, 200 req/s measure ~8 min.
  - **Dev loop** (2026-11-17, after "why do you need to re-run so many times"): look up APIs, flags and versions before writing; time-box infrastructure experiments to 2 attempts, then take the documented configuration and record the deviation; never `|| true` a step the fix depends on; read test-report counts, not quiet logs; batch fixes into one push; record every multi-attempt problem in the knowledge base.
  - **Bulk files** (2026-11-17): 10M-record files in ≤ 5 minutes including per-record DB validation (Flink batch, hybrid validation freshness; ADR-011).
  - **Resilience is mandatory** (2026-11-17): outbox, idempotency, circuit breakers, rate limiters, throttling, DLQ with retries and the other error-handling mechanisms (Temporal sagas, SmallRye Fault Tolerance).
  - **Edge app** (2026-11-17): full code plus emulation (Android emulator, simulated TEE and NFC), packaged with Tauri 2 mobile.
  - **Earlier "build every PDF component" rule** (2026-11-17) is superseded by 2026-11-20: the PDF is a reference; better alternatives are offered as choices.
- Licence, footprint, alternatives, contract-first and dev-loop rules: see [CONVENTIONS.md](../CONVENTIONS.md).

## Decided
| Date | Question | Owner's answer |
|---|---|---|
| 2026-11-20 | SQL engines (PDF §5.6 Trino + StarRocks) | **Trino only.** StarRocks dropped (overlapped Trino on Iceberg; ~2.5 GB requested; most lakehouse install failures). Superset queries Trino. |
| 2026-11-20 | Vector search (PDF §5.7 Weaviate) | **pgvector on the shared Postgres** instead of Weaviate (no new service; SQL joins with our data). |
| 2026-11-20 | Feature store (PDF §5.7 Feast) | **Keep Feast, minimal:** registry in Postgres, online store in Valkey, offline store on Iceberg via Trino. |
| 2026-11-20 | Lineage/catalog (PDF §5.8 DataHub) | **OpenLineage + Marquez** instead of DataHub (DataHub needs OpenSearch + GMS/frontend, ~3–5 GB, and nothing emitted lineage yet). Marquez on the shared Postgres; emitters from Trino, dbt, Flink. Owners/PII tags as dbt meta, Apicurio labels, Polaris properties. |
| 2026-11-20 | Business rules (owner: "do as you seem best fit for the requirements") — evidence custody | Operator key in OpenBao transit (non-exportable, signs via API); the witness is a separate notary service with its own key, never the operator. Dev keeps generated keys. *Implemented on wip-tier-history (2026-11-20): exchange signers + `services/notary`; OpenBao transit mount/key/auth still to wire after the security profile converges.* |
| 2026-11-20 | — collateral basis and default tier | V = A (the partner's exposure at the merchant). New partners start COLD_START (φ 2.0) and become ESTABLISHED after verified deliveries. *Implemented on wip-tier-history (2026-11-20): threshold `reputation.established_after_deliveries: 3` in vertical.yaml, also needs reputation ≥ 80; ENTERPRISE only by agreement, never from history.* |
| 2026-11-20 | — `min_minor` floors | FR-01 keeps ₹500 (minimum stake; small next to typical order values). Other verticals set theirs when they go live. |
| 2026-11-20 | — FR-01 return window | 10 days before yield Y is released (covers 7–10-day return policies plus confirmation lag). Applied in vertical.yaml. |
| 2026-11-20 | — reputation cold start, V_ref | Partners without history rank at the fixed prior 80; self-reported scores are ignored (gameable). V_ref stays ₹50,000. Applied in exchange-svc. |
| 2026-11-20 | — money letters | v4.1 as implemented: A charged at the merchant, B = A + Y + F paid by the buyer; the PRD is the one to correct. |
| 2026-11-20 | Payment routing: saga vs DIRECT | Keep saga (Temporal). |
| 2026-11-22 | Authorisation switch: jPOS? | Keep the moov-io/iso8583 scheme simulator for now; migrate to jPOS (AGPL-3.0, OSI) later. jCard is not an option: it is source-available from Transactility, not open source (ADR-001). |
| 2026-11-22 | Fraud scoring and FRM | Use Tazama (tazama-lf), vendored into the repo, with DIFME's stack in place of its redundant components (NATS → Kafka, own Postgres/Valkey/Keycloak → shared ones, Elastic APM/ELK → OpenTelemetry/Alloy/Loki). ADR-023. |
| 2026-11-20 | Canary SLO thresholds | "Best possible value achievable": p99 ≤ 400 ms (measured worst p99 346 ms under the 200 req/s baseline, ~15 % headroom); success rate stays ≥ 99.5 %. Tighten as the payment path speeds up. |
| 2026-11-20 | Argo CD → Flux? | Keep Argo CD. |
| 2026-11-20 | Istio → Cilium mesh? | Keep Istio ambient (fixed for Cilium the same day). |
| 2026-11-20 | Kafka: replace Strimzi brokers with `apache/kafka-native`? | Allowed only if no functionality is lost. Before any switch: list everything Strimzi provides today (KRaft node pools, entity/topic operator and KafkaTopic resources, listeners/TLS, metrics, Debezium/Apicurio/Flink/RisingWave/KEDA integrations, rolling upgrades), show each one covered by the replacement, then A/B the footprint. |
| 2026-11-20 | Istio ambient broke the core services on Cilium (probes from 169.254.7.127 dropped, CNI chaining, k3s paths). Fix, replace with Cilium mesh, or mesh off in dev? | Fix Istio ambient (three config changes). |
| 2026-11-21 | Real payment-system simulators: PSP (PA/PG), payment hub, CBS, ISO 8583 adapter, card-scheme simulator | PSP: Juspay Hyperswitch (Apache-2.0). CBS: Apache Fineract (Apache-2.0, PostgreSQL). Payment hub: **built on our stack** (Temporal/Fluxnova), not Mifos PH-EE, which needs Zeebe (Camunda License 1.0, not OSI) + Operate + Elasticsearch (several GB). ISO 8583 + scheme simulator: **moov-io/iso8583** (Apache-2.0) rather than jPOS (AGPL-3.0). Sourcing: **copy the source into our repo** (vendor/, pinned release, no git history), build from it. |
| 2026-11-21 | Payment hub: reuse Mifos Payment Hub EE (clarifies the row above) | **Vendor Mifos PH-EE (MPL-2.0) and replace only Zeebe with Fluxnova**: its BPMN flows run on Fluxnova after mechanical edits (zeebe:taskDefinition → external task topic, message subscriptions → message correlation, FEEL conditions → Fluxnova expressions); its Zeebe job workers become Fluxnova external-task workers; connectors, Camel routes and DTOs are kept. The interim Temporal hub (`services/core/payment-hub`) stays until the port passes the same end-to-end tests, then the exchange points at PH-EE and the interim hub is deleted. |
| 2026-11-21 | Mojaloop for the settlement leg (central switch) | **Mojaloop Testing Toolkit in hub mode** (mojaloop/ml-testing-toolkit, Apache-2.0) plays the central switch (party lookup, quotes, transfers, callbacks); **mojaloop-simulator** (Apache-2.0) plays the other bank (payee DFSP) behind it; **PH-EE's Mojaloop connector** (ph-ee-connector-mojaloop-java, MPL-2.0) connects the payment hub. Real switch core (central-ledger etc., MySQL + Kafka) not now. Owner also asked: nothing but free and open source anywhere; deep-scan the code for anything missed. |
| 2026-11-21 | Regulator node (real-time stream to a regulator node)? | Not required: regulatory reporting is report/file based. The exchange produces downloadable order reports (CSV/JSON; JSON signed by the exchange operator key, verifiable with GET /v1/exchange/keys). The Regulator node page is removed from the live apps. |
| 2026-11-21 | (agent, business rule) A mandate's 5 % deposit rule and the FR-14 per-order collateral contradicted: a new partner's factory-made mandate (₹2,000 deposit) registered but could never win an ₹8,000 order (collateral ₹5,760). | Required deposit = max(5 % of budget, collateral on the mandate's largest allowed order at the partner's current tier); the exchange computes it at registration, the factory shows the same. Owner may revisit the parameters (α 0.20, γ 1.8, φ 2.0 new / 1.0 established). |
| 2026-11-21 | (agent) Partner custom rules on the live exchange | The exchange compiles the structured table itself and runs it at every bid (REJECT: no bid; FLAG: bids, noted in evidence). FEEL only; functions, loops and Java calls refused. Intents carry optional order details (merchant, category, …) for them. |
| 2026-11-20 | Harbor fails its first migration on YugabyteDB (it supports PostgreSQL only). Where should its database live? | Shared platform Postgres (ADR-019). |
| 2026-11-20 | OpenBao is 3-replica HA (unschedulable on one node) and never initialized. How should it run in dev/verification? | 1 Raft replica plus a bootstrap Job (init, unseal with a dev key in a Secret, PKI mount and Kubernetes auth for SPIRE); HA stays for production overlays. |
| 2026-11-20 | attestation-verifier has no source and no image yet. What until the code exists? | Take it out of the security profile for now (Veraison stays); it returns with its code. |
| 2026-11-20 | Commit identity (the vendor rule) | Commits use `pratikmohanty1294@users.noreply.github.com`; only unmerged branch commits were re-authored, main history left as is. |
| 2026-11-20 | Remove YugabyteDB (~440 MiB in dev) and move everything to the shared Postgres? | Keep it; measure first what the move would save on the runners and bring the numbers before any change. |
| 2026-11-20 | Where does the agent live, given nothing may run on the PC? | A cloud agent session (it can be driven from a phone). Heavy work runs in GitHub Actions. |
| 2026-11-20 | How does work continue with zero local execution? | Cloud session; even `git` and `gh` move off the PC. |
| 2026-11-20 | formio 4.11 hard-requires the proprietary `@formio/feature-flags`. Which way? | Shim it out (MIT stand-in in `vendor/formio/server/shims/`). |
| 2026-11-19 | Codespace blocked (HTTP 402 billing). How to continue? | Free alternative: a free-tier arm64 cloud VM. Keep retrying the cloud VM (capacity) and keep the Codespace alive for when the monthly hours reset. |
| 2026-11-19 | Saga routing vs DIRECT | Measure first (A/B done, see status.md); the routing choice itself is still open below. |
| 2026-11-19 | Install order for the remaining profiles | The recommended order above, one at a time. |
| 2026-11-19 | Sizing approach | Dev right-sizing overlay (Kyverno, CPU requests ÷ 4); measure after right-sizing with everything up. |
| 2026-11-19 | Argo CD controller restart loop | Reinstall Argo CD 2.14, then rebuild the Codespace. |
| 2026-11-18 | Memory pressure | Trim real memory first; Tier 1 (zswap + swap + kubelet LimitedSwap): yes; proceed with the control-plane CPU fix. |
| 2026-11-18 | Keep-alive token for long jobs | Store it as the user-level Codespaces secret `GH_TOKEN`, scoped to this repo (owner to rotate to a narrower token). |
| 2026-11-18 | RisingWave metadata store; S3 for streaming | Shared Postgres; SeaweedFS moves into the streaming profile. |

## Open (owner to decide)
| Since | Question | Context |
|---|---|---|

## Product requirement context (owner's questions, 2026-11-17)
`docs/GOALS.md` still says "product goals: to be defined by the owner". The owner's research questions show the direction of DIFME/DiscountAI (ADR-020):
- Is there an aggregator (like quick-commerce APIs) that gives one integration for product-feed discovery across merchants?
- How to get the best price for a product, including affiliate coupons? Do affiliate coupons apply when merchant PWAs open inside affiliate sites?
- How does agent payment-credential handover work in recently launched agent wallets, which global standards apply, and does it happen in the browser or through APIs?
- Paying with the user's own card through an agent wallet (Prava skills installed for this).

## Carried-over pending items
- Measure the memory saving of running payments + tools on the shared Postgres instead of YugabyteDB (owner asked for numbers before any move).
- Resume `event-archive` once the lakehouse profile (Polaris) is up.
- ~~Resume `event-archive` once the lakehouse profile (Polaris) is up.~~ Done 2026-11-20: it moved to the lakehouse profile (`flink-archive`).
- A startup smoke test for config parsing (the `.properties` inline-comment crash only showed at runtime).
- The Makefile `build` and `test` targets still name `services/hub`, `services/attestation` and `edge/core`, which don't exist yet.

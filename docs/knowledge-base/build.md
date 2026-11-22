# Build, CI and toolchain

| Symptom | Cause | Fix |
|---|---|---|
| `package org.apache.flink.api.java.utils does not exist` | Flink 2.x moved `ParameterTool` | `org.apache.flink.util.ParameterTool` |
| Surefire: conflicting JUnit versions | `flink-test-utils` pulls an old vintage engine | import `junit-bom`, exclude `junit-vintage-engine` |
| Flink MiniCluster: `Could not deserialize stream node` under `mvn exec:java` | Maven's classloader | `exec:exec` (separate JVM) |
| `-Dnative` builds a JVM jar | no `native` profile in the POM | `-Dquarkus.native.enabled=true -Dquarkus.package.jar.enabled=false` |
| Native image fails in Temporal's shaded Netty | Temporal SDK isn't native-image clean | process-gateway runs on JVM + AOT cache (ADR-012) |
| pnpm `ERR_PNPM_IGNORED_BUILDS` | pnpm ≥ 11 blocks install scripts | `allowBuilds` map in `pnpm-workspace.yaml` |
| MF DTS generation fails | remotes are runtime-registered | `dts: false` in the Module Federation plugin |
| Angular: `Failed to read index HTML` | web-component bundle has no page | `"index": false` |
| Trivy action tag not found | pinned tag doesn't exist | run the Trivy CLI from its pinned image |
| Nginx image blocked by Trivy (brotli CVE) | base image lags Alpine fixes | `apk upgrade` in the Dockerfile |
| Windows commits lose executable bits | Git on Windows | `git update-index --chmod=+x` |
| Shell heredocs mangle backslashes (Windows Bash tool) | quoting layers | edit files with editor tools or patch files, never inline JSON/regex in shell |

### `release version 25 not supported` in the Codespace (CI green)
- **Root cause:** the devcontainer installed only JDK 21 (for Flink), so `make check AREA=core` had never actually run in the Codespace.
- **Fix:** the devcontainer installs Temurin 25 with 21 as an additional version, and `ci/check.sh` selects the JDK per area (core → 25, flink → 21).

### JVM memory budget in containers (measured 2026-11-18, cmd-svc at 200 req/s)
- `MaxRAMPercentage=70` with a 320 MiB limit left about 96 MiB for metaspace, code cache, thread stacks and Netty direct buffers, so cmd-svc was OOM-killed under load (exit 137).
- Now 55% heap, `MaxDirectMemorySize=32m`, and cmd-svc at 448 MiB (it carries Hibernate, the Temporal SDK, gRPC and the Redis client). Re-measure before shrinking.
- Quarkus Redis client defaults (6 connections, 24 waiters) saturate at a few hundred cache calls per second: `ConnectionPoolTooBusyException`. Size `quarkus.redis.max-pool-size`/`max-pool-waiting` to the call rate.

### Payment write path: what pg_stat_statements and the cmd-svc metrics showed (2026-11-19)
- **Profile** at 15 req/s, ~630 payments, YugabyteDB 2.25, one tablet per table:

| Statement | Calls | Mean | Cause |
|---|---|---|---|
| Full-row `UPDATE core.payment` | 1097 | 10.5 ms | `PaymentService.accept()` set `p.dispatch` after `persist()`, so Hibernate flushed an INSERT plus an UPDATE of every column, including the indexed `idempotency_key` and partial-index columns. |
| `SELECT core.payment` by id | 1097 | 3.4 ms | `PaymentRepository.record()` looked up the id first, even for a brand-new UUIDv7 payment. |

- **Fix:** dispatch mode written in the INSERT, no lookup for `PaymentInitiated`, and `@DynamicUpdate` so status changes write only the changed columns.
- **The dominant cost was not SQL:** about 55–60 ms of statements per payment, but p50 646 ms.
  - `startSaga` (Temporal, ~160 ms under load) ran inline in the HTTP request, holding a worker thread and an adaptive-limiter slot. The class's own contract said "the client already has its answer".
  - **Fix:** `AsyncDispatcher`, a bounded queue drained by virtual-thread workers, with inline fallback when the queue is full. Saga start is idempotent, and `PaymentSweeper` recovers any lost job.
- **Other observations:**
  - YugabyteDB WAL fsync averages 8.2 ms on the Codespace disk.
  - Colocation would gain little here, because every table is already a single tablet on the single node.
- **How to profile:** `CREATE EXTENSION pg_stat_statements` and `SELECT pg_stat_statements_reset()`, run light load (`ci/measure.sh 15 45s`), then sort by `total_exec_time`. Read the cmd-svc metrics through the API server: `kubectl get --raw /api/v1/namespaces/core-platform/services/<svc>:http/proxy/q/metrics` (the image has no curl).

### Image workflow: attestation/provenance steps fail on Sigstore network timeouts (2026-11-19)
- **Symptom:** `InternalError: error fetching tlog entry ... network timeout at: https://rekor.sigstore.dev`, in "Attest SBOM" or "SLSA provenance".
- **What it means:** the image was already built, scanned and pushed by then, so deployments are unaffected. Only the attestation is missing.
- **Fix:** `gh run rerun <run> --failed` re-runs only the failed jobs and restores the attestation.

### Agrona 2.x on Java 25 needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`
- **Symptom:** `IllegalAccess ... cannot access class jdk.internal.misc.Unsafe` / `NoClassDefFound: Could not initialize class org.agrona.BufferUtil`.
- **Fix:** set the export in the module's surefire `argLine` (`exchange-matching/pom.xml`) and in any service JVM that loads Agrona.

### Matching engine vs PRD NFR-02 (measured 2026-11-19, Codespace, `MatchingPerfTest`)

| Measure | Result | NFR-02 target |
|---|---|---|
| Per bid, end to end (off-heap MPSC ring + single-writer engine) | 117 ns | < 100 µs |
| Rank + close of a 61-bid auction | p50 1.6 µs, p99 3.0 µs | p99 < 5 ms |

### `.properties` files have no inline comments (2026-11-19)
- **What happened:** `difme.flagd.port=8015   # flagd sync port` made the whole remainder the value. cmd-svc crash-looped with `Failed to load config value of type int for: difme.flagd.port`. Unit tests passed because they never start Quarkus.
- **Rule:** comments go on their own `#` line.
- **Guard:** `ci/check.sh core` now fails on `key=value   # …` in any `application.properties`.

### formio server crash-looped on `matchMedia is not defined` (cluster-verify 2026-11-20)
- **Symptom:** `ReferenceError: matchMedia is not defined` in `node_modules/inputmask/dist/inputmask.js` at startup; the formio pod never became ready.
- **Root cause:** the new lockfile resolved the server's `inputmask ^5.0.8` to 5.0.10, which calls the browser-only `matchMedia` while the module loads. 5.0.9 (what `@formio/core` pins) has no such call.
- **Fix:** `vendor/formio/server/package.json` pins `inputmask` to 5.0.9 and overrides it as `$inputmask` everywhere; lockfile regenerated.
- **Rule:** a lockfile refresh can pull a browser library's new patch release into a Node server. Verify the server starts (cluster-verify process profile) whenever its lockfile changes.

### formio 4.11 server needs its VM bundles built (cluster-verify 2026-11-20)
- **Symptom:** after the inputmask fix, startup failed with `ENOENT … src/vm/bundles/core-lodash-moment-inputmask.js`.
- **Root cause:** 4.11 evaluates form logic in isolated-vm sandboxes loaded from webpack bundles generated by `npm run build`; the image installed production dependencies only and never ran the build.
- **Fix:** `deploy/images/formio/Dockerfile` does a full `npm ci`, runs `npm run build`, checks the bundle exists, then `npm prune --omit=dev`. Verified in a cloud container: four bundles, about 4.8 MB.
- **Rule:** after re-vendoring an upstream server, diff its `scripts` for new build steps.

### Reading a field through a CDI client proxy gives the proxy's copy (found 2026-11-20)
- **Symptom:** a test set a simulator limit through `@Inject Exchange exchange; exchange.rails...`, and the service ignored it.
- **Root cause:** `@ApplicationScoped` beans are injected as client proxies (generated subclasses). Methods delegate to the real instance; **fields don't**: the proxy has its own, separately initialised copy.
- **Fix:** expose state through a method (`Exchange.rails()`), keep the field private.

### Contract tests (Schemathesis, ADR-014) found 500s on null bodies (2026-11-20)
- **What:** `core-services` now starts exchange-svc and runs Schemathesis 4.32.7 against the OpenAPI contract (`api/openapi/schemathesis.toml` pins the live pack so requests reach the real logic). With random pack names everything stopped at 404; with `fr01-buy` it found a JSON `null` body crashing intents and mandates (NullPointerException → HTTP 500).
- **Fix:** null bodies are 400 in intents, mandates and bids; regression test `nullBodiesAreBadRequestsNotServerErrors`. 1,220 generated cases then passed with no server errors.
- **Local run:** start the jar with `--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED` (Agrona), as the Dockerfile does.

### formio vs FerretDB 2: "listCollections requires authentication" (cluster-verify 2026-11-20)
- **Root cause:** FerretDB 2 enables authentication by default and validates client credentials against PostgreSQL roles (SCRAM-SHA-256 only); formio's `mongo-url` had none.
- **Fix:** `dev-secrets.sh` gives formio `mongodb://difme:<pw>@ferretdb…/formio?authMechanism=SCRAM-SHA-256` (the shared Postgres role that already backs FerretDB).
- **Next layer, same day:** `schema "documentdb_api" does not exist`. Our ConfigMap was mounted over the postgres-documentdb image's `/docker-entrypoint-initdb.d`, hiding the image's own init (which creates the DocumentDB extension). Creating the extension in our own script failed and stopped the init chain, so Temporal's database was never created. **Fix:** mount each of our scripts by `subPath`, so the image's init runs too.
- **Next layer:** `Cannot find module 'resourcejs'`. Upstream formio 4.11.0 depends on `resourcejs ^2.6.2` (MIT), but it was missing from our vendored package.json. A diff against `npm view formio@4.11.0 dependencies` showed it was the only gap. **Fix:** declared and locked (2.6.3). **Rule:** after re-vendoring, diff the dependency list against the published package.
### docker.io rate limits in image builds (2026-11-20)
- **Symptom:** a flink-jobs image leg failed with HTTP 429 from docker.io when ~25 image jobs started together (anonymous pulls).
- **Fix:** `_image.yml` configures BuildKit with `[registry."docker.io"] mirrors = ["mirror.gcr.io"]`; a public pull-through cache serves rust, node, golang, debian and eclipse-temurin, and BuildKit falls back to docker.io for anything the mirror lacks. No Dockerfile changes.
### JDK 25 in a cloud session without Adoptium (2026-11-21)
api.adoptium.net and GitHub release downloads are blocked by the session proxy, but conda-forge is reachable:
`curl -fsSLO https://conda.anaconda.org/conda-forge/linux-64/openjdk-25.0.5.1-h1602c4f_1.conda`, unzip it, then
decompress `pkg-*.tar.zst` with the Python `zstandard` package (no `zstd` binary here) and untar; `JAVA_HOME` is
`<dir>/lib/jvm`. Runs `mvn test` for services/core (46 exchange tests) and the packaged exchange-svc locally.
### Payment-rail builds: vendored Fineract, Hyperswitch (2026-11-21)
- **Fineract** derives its version from git tags; inside DIFME's repo there are none ("couldn't find matching tag in
  shallow git repository" at build.gradle:147). Build with `VERSIONING_DISABLE=true`; the jar is
  `fineract-provider/build/libs/fineract-provider.jar` (no version suffix). Maven Central answered 429: a Gradle init
  script puts Google's Central mirror first and adds the plugin portal back (`deploy/images/fineract/maven-mirror.gradle`).
  First start on an empty database runs Liquibase for ~2.5 min; 866 MiB RSS under load with `-Xmx512m`.
- **Hyperswitch** needs `libprotobuf-dev` next to `protobuf-compiler` (well-known protos such as
  `google/protobuf/empty.proto`; Debian only pulls them in as a *recommended* package, so `--no-install-recommends`
  breaks the build in `grpc-api-types`). Its 555 v1 migrations run with plain psql (`deploy/images/hyperswitch/migrate.sh`,
  diesel-compatible bookkeeping) in ~40 s.
- **Temporal workflow ids** are not idempotent by default: once a workflow finishes, the same id can start again. The
  payment hub sets `WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE` and answers repeats from the first run.
- **Fineract** `Idempotency-Key` header: a repeated command is answered from cache (`x-served-from-cache: true`), not
  booked twice. Savings accounts and clients can be found by `external-id`, so callers need no id mapping.
### Mifos PH-EE with Mojaloop (2026-11-21)
- **Licence trap:** PH-EE's Mojaloop connector depends on `org.mifos:interop-ilp-conditions`, whose LICENSE reads
  "All Rights Reserved. Distribution, reproduction or use is prohibited without permission". Replaced (init script) by
  `services/fspiop-ilp-models` + vendored Apache-2.0 java-ilp-core. Also `org.json` < 20231013 is under the JSON License
  (not OSI). Check every transitive dependency's licence, not just the project's own.
- **ILP v1 wire format:** java-ilp-core 0.6.x writes payment packets without the length-prefixed envelope and the
  extensions byte; Mojaloop (ilp-packet-v1) uses the final format with long-form OER lengths. Compare bytes, don't trust
  the version number.
- **Spring dependency-management** re-applies declared versions after Gradle `eachDependency` rules registered earlier;
  register DIFME's rules again in `afterEvaluate`.
- **Restarting a Spring Boot service:** SIGTERM can take >30 s (webServer shutdown timeout); wait for the old process to
  exit before starting the new one, or the old code keeps serving (we lost time to that).

## Hyperswitch router needs more than 16 GB to compile (2026-11-21)
In a 16 GB / 4 CPU container (nothing else running, `-j 2`, `CARGO_INCREMENTAL=0`), `cargo build --profile
release-fast --bin router` was killed by the kernel three times: on `router` with opt-level 1, and on
`hyperswitch_connectors` (peak 14,989 MB used) with router at opt-level 0. The build tree also needs ~8 GB of disk.
Build the image on a machine with at least 24 GB RAM (or with swap), or turn off router features DIFME doesn't use.
**Fix (2026-11-21):** the `hyperswitch` image job passes `swap: 24G` to `_image.yml`, which frees the runner's
preinstalled SDKs and adds a swapfile (on `/mnt` where it has room, else the root disk) with zswap via
`ci/image-disk.sh swap` before building. Prevention: any image whose compiler peaks near the runner's RAM gets the same
input rather than lower optimisation.


**Measured per crate (2026-11-22, 16 GB / 4 CPU container, peak RSS of each rustc):** diesel 11.4 GB (its
`128-column-tables` feature, needed for the 97-column `payment_attempt`), router 13.6 GB at opt-level 0 (killed above
8.6 GB at opt-level 1 when other crates ran alongside), hyperswitch_connectors 8.1 GB, diesel_models 3.9 GB. The
router's memory is the compiler front end, so a lower optimisation level helps only so far. Turning features off is not
an option: hyperswitch_connectors does not compile without `payouts`/`frm` (1,348 errors) and router not without
`kv_store` (12 errors); upstream builds only full feature sets. **Fix:** `-j 1` so the peaks never overlap, router at
opt-level 0, default features; the 24 GB swapfile stays as a backstop.

**Resolved (2026-11-22):** the Hyperswitch image builds on standard 16 GB runners for both platforms (run 44997634903:
amd64, arm64 and the signed multi-arch manifest green). Two fixes: `-j 1` with the router at opt-level 0 (memory, above),
and on arm64 the LLD linker: the unoptimised router's code exceeds a direct branch's ±128 MB reach, so GNU ld failed with
"relocation truncated to fit: R_AARCH64_CALL26"; LLD inserts range-extension thunks
(`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld"`). Build time ≈ 2.3 h per platform.

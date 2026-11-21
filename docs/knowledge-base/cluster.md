# Cluster: k3d in Codespaces

### Pods can't reach the API service (`10.43.0.1`), CoreDNS / local-path / metrics-server crash
- **Root cause:** Cilium's full eBPF kube-proxy replacement doesn't work reliably inside Kubernetes-in-Docker. Host-network pods in particular can't reach ClusterIPs.
- **Fix:** Codespace runs Cilium **alongside k3s kube-proxy** with iptables masquerade (`deploy/platform/kube-system/cilium/values.yaml`, ADR-013). RKE2 clusters keep full kube-proxy replacement.
- **Prevention:** don't re-enable `kubeProxyReplacement` in k3d. Four variants were tried: legacy host routing, cgroup root, node entrypoint mounts, BPF masquerade. All failed or regressed.

### `BPF masquerade requires NodePort`
- **Root cause:** `bpf.masquerade: true` needs kube-proxy replacement's NodePort support.
- **Fix:** `bpf.masquerade: false` whenever kube-proxy replacement is off.

### Pods can't resolve DNS (CoreDNS → `172.18.0.1:53` i/o timeout)
- **Root cause:** k3d points nodes at the Docker gateway and relies on an iptables redirect that only covers node-originated traffic, not pod traffic.
- **Fix:** `K3D_FIX_DNS=0` plus k3s `--resolv-conf=/etc/difme/resolv.conf` (`deploy/bootstrap/k3s-resolv.conf`, mounted by `make cluster`).

### YugabyteDB crash loop: `Required ulimit values too low … open files 1024`
- **Root cause:** k3d node containers inherit Docker's default nofile limit.
- **Fix:** `options.runtime.ulimits` nofile 1048576 in `deploy/bootstrap/k3d.yaml`. Kafka and Cassandra need it too.

### Pods sit in `ContainerCreating` for 10+ minutes; dependants crash-loop meanwhile
- **Root cause:** large images (YugabyteDB ~2 GB, Temporal, FoundationDB) were downloaded serially, and again after every cluster rebuild.
- **Fix:**
  - Persistent pull-through caches (`make registries`) for docker.io, ghcr.io, quay.io and registry.k8s.io survive `make destroy`.
  - `make prefetch PROFILE=…` (run by `make up`) pre-pulls images 3 at a time with retry and exponential backoff.
  - The kubelet runs up to 3 parallel pulls.
- **Prevention:** add new images to manifests normally; prefetch discovers them from the rendered manifests.

### Node load average 38 on 4 cores, SSH timeouts, everything `Progressing` at once
- **Root cause:** `make up PROFILE=core` ran while the base profile was still converging, so 23 apps synced simultaneously (a thundering herd of image pulls, CRD installs, webhooks and Argo CD diffs).
- **Fix:**
  - `ci/up.sh`, run by `make up`, waits for already-deployed apps, then applies a profile **wave by wave**, waiting for each wave to be healthy.
  - Argo CD concurrency is sized for a small node (`controller.status.processors=6`, `operation.processors=3`, `kubectl.parallelism.limit=4`).
- **Prevention:** never apply several profiles back-to-back without waiting; `make up` enforces it.

### `gh codespace ssh` fails: no SSH server
- **Fix:** the `ghcr.io/devcontainers/features/sshd:1` feature in `.devcontainer/devcontainer.json`.
- **Note:** a rebuild uses the repo copy already inside the Codespace, so a devcontainer change needs a new Codespace (or `git pull` first).

### Post-create stopped half-way; several CLIs missing
- **Root cause:** `set -e` plus one failed download (the pinned Trivy release asset).
- **Fix:** every tool installs independently (`step` wrapper), and Trivy runs from its pinned image.

### TigerBeetle OOM-killed at 1.5 GiB
- **Measured:** about 2.1–2.3 GiB RSS at 0.16.78 regardless of cache flags. It allocates statically, and its 1 GiB journal dominates.
- **Fix:** lean caches (`--experimental --cache-grid=128MiB --cache-accounts/transfers=32MiB --cache-transfers-pending=16MiB`, saves ~200 MB) and a 2.5 GiB limit.
- **Also:** no `IPC_LOCK` capability; it violates baseline Pod Security and isn't needed.

### Default-deny blocked operators and cross-namespace flows
- **Root cause:** the generated CiliumNetworkPolicy allowed only same-namespace traffic and DNS.
- **Fix:** also allow the kube-apiserver and traffic between DIFME namespaces (`difme/workload-type` label). The mesh adds per-identity rules on top.

### Kong pod stuck at 1/2 Ready
- **Root cause:** Kong's ingress controller lacked RBAC for the Gateway API resources it auto-watches.
- **Fix:** Kong runs DB-less from its static config, so the controller is disabled (lighter too).

### db-init: `/sql/init.sql: No such file`
- **Root cause:** the Job never mounted its ConfigMap. Caught only at runtime, because a dry run doesn't execute containers.
- **Prevention:** check `volumes`/`volumeMounts` whenever a configMapGenerator is added.

### YugabyteDB: "Write to tablet rejected … insufficient disk space"
- **Symptom:** db-init failed, and so did every role/database creation behind it (Temporal: `role "temporal" does not exist`).
- **Root cause:** the Codespace's 32 GB persistent disk was 92% full. 14 GB of it was container image layers inside the k3d node, which are re-fetchable and already stored a second time in the registry caches. Real volume data was 1.2 GB.
- **Fix:** `make cluster` bind-mounts the node's containerd store on the large ephemeral disk (`/tmp`, 118 GB). PVs and registry caches stay persistent; after a Codespace stop, layers re-pull from the local caches.
- **Prevention:** `df -h /` belongs in every "why is X failing" check; databases refuse writes well before 100%.

### k3d create hung at "Starting node server-0"
- **Symptom:** kubelet exited with `unknown flag: --max-parallel-image-pulls`.
- **Root cause:** `maxParallelImagePulls` is a KubeletConfiguration field, not a flag. The setting was added after the last cluster creation, so it was never exercised.
- **Fix:** a kubelet drop-in, `deploy/bootstrap/kubelet-difme.conf`, mounted into `/var/lib/rancher/k3s/agent/etc/kubelet.conf.d/` (k3s ≥ 1.32).
- **Prevention:** bootstrap changes aren't validated until a cluster is created; recreate after changing them.

### Long jobs died with the SSH session
- **Root cause:** `gh codespace ssh` drops after long idle periods, killing foreground `make` runs.
- **Fix:** start long jobs with `nohup … &` in the Codespace and poll the log instead.

### Non-root pods: `exec: "/coredns": stat /coredns: permission denied`
- **Symptom:** CoreDNS and Hubble crash-looped, while root pods (Cilium) ran fine. This appeared after moving the containerd store to `/tmp`.
- **Root cause:** Codespaces' `/tmp` carries a default ACL, so new directories come out `drwxr-xrw-+` (no traverse for others), and non-root containers can't reach their image layers.
- **Fix:** `make cluster` recreates the image directory, clears ACLs (`setfacl -R -b -k`) and sets `chmod 755` before k3d starts.
- **Prevention:** a `+` in `ls -ld` means an ACL is in play; check it whenever a bind mount comes from a new host path.

### Containerd store on `/tmp`: abandoned after 2 attempts (time-box)
- **What happened:** moving image layers to the 118 GB ephemeral disk broke every non-root pod (`stat /coredns: permission denied`). `setfacl` isn't installed in the Codespace, and `|| true` hid that, so the inherited default ACL was never cleared.
- **Decision:** revert to the persistent disk and bound usage with kubelet image GC (70% → 60%) plus eviction thresholds instead. It's simpler, with no special host setup.
- **Lesson:** never `|| true` a step the fix depends on. Fail loudly, or check the result (`ls -ld` shows `+` while an ACL remains).

### Core profile, first live run: four failures found together
- **Quarkus services crash:** `/tmp/vertx-cache: Read-only file system`. Our mutate policy sets `readOnlyRootFilesystem`. **Fix:** a 64 Mi disk-backed `emptyDir` at `/tmp` in the service template.
- **Temporal schema:** `permission denied to create database`. db-init owns database creation and the role has no CREATEDB. **Fix:** `schema.createDatabase.enabled: false`.
- **flagd blocked by `restrict-registries`:** the rule ported from Gatekeeper (ADR-015) lacked the upstream allowlist. **Fix:** explicitly allow pinned upstream images, plus `docker.io/library/*` as before.
- **Kyverno reports controller OOMKilled at 128 Mi:** **fix:** limit 320 Mi, to be refined from the baseline.
- **Lesson:** a policy port must be checked against every live workload it matches. Server dry runs of the policy alone pass, so dry-run the *workloads* against the new policy as well.

### Codespace restart: the whole cluster down, pods stuck `Unknown`
- **Trigger:** the Codespace stopped on its idle timeout and restarted. The k3d node came back with a new IP (172.18.0.6 → .3).
- **Root cause:** `install.sh` pinned Cilium's `k8sServiceHost` to the node IP at install time, so the agent kept dialing the old address. No CNI means no pod starts, and Kyverno's fail-closed webhooks then blocked everything else.
- **Fix:** `k8sServiceHost: 127.0.0.1` (single-server; agent and operator use the host network). One value in the Cilium values file serves both Helm bootstrap and Argo CD. Their earlier disagreement was the cause of the `cilium` OutOfSync flapping.
- **Recovery:** after the CNI is back, force-delete `Unknown`/`Error` pods so controllers recreate them, starting with `security` (Kyverno).
- **Prevention:** never bake an IP that can change into config. Also raise the Codespace idle timeout (account setting, up to 240 min) so long background jobs don't lose their host.

### Disk: 32 GB root vs 118 GB /tmp (measured 2026-11-18)
- Codespace root (`/`, `/workspaces`) is 32 GB; `/tmp` is a separate ~118 GB ephemeral disk (emptied on Codespace restart).
- At ~86% root use the kubelet (nodefs 8% threshold) evicted pods; they restarted, re-pulled and refilled the disk — an eviction loop that also killed Temporal's schema Job midway (half-migrated DB).
- Each image existed three times: registry cache (~4.9 GB), containerd content (~2.3 GB), unpacked snapshots (~6.2 GB).
- Fix: registry pull-through caches are bind mounts under `/tmp/difme-registry/` (pure caches, safe to lose). Node containerd stays on root (moving it to /tmp broke non-root pods earlier).

### Long jobs without the client computer (2026-11-18)
- `bash ci/bg.sh NAME cmd…` runs a job under nohup in the Codespace. A keep-alive (`gh codespace ssh` to itself every 4 min) runs only while the job does, so the 60-minute idle timeout can't stop it midway, and the Codespace still idles out normally afterwards.
- Needs a one-time `gh auth login -s codespace` inside the Codespace; the default Codespace token has no `codespace` scope.

### Containerd store on `/tmp`: resolved (2026-11-18, third approach after the time-box)
- **Root cause (known):** `/tmp`'s default ACL (`default:other::rw-`, no traverse) is inherited by new directories, so non-root containers can't reach their image layers.
- **What changed:** install `acl` (`setfacl` was missing before, and `|| true` hid that), then clear the ACL on `/tmp/difme-containerd`. Verified on a throwaway cluster: CoreDNS and a non-root (uid 1000) busybox both run.
- **Restart case:** a Codespace restart empties `/tmp`, and Docker recreates the bind source with the bad ACL. `postStartCommand: ci/image-disk.sh heal` fixes the ACL and restarts the node; images re-pull from the registry caches, or from upstream if those were wiped too.
- **Gain:** about 8.4 GB off the 32 GB root disk (core alone), which leaves room for the streaming and observability profiles.

### Root disk filled to 95%, eviction storm (found 2026-11-18)
- **Main cause: SeaweedFS reserved disk.** With `-master.volumeSizeLimitMB=1024`, each new volume reserved about 1 GB on disk. The default collection got 7 volumes and the RisingWave bucket 13 more, so about 21 GB was reserved for a few KB of data. Fix: 64 MB volumes and `-master.volumePreallocate=false`. Check a store's real disk use with `du`, not file sizes.
- **Smaller cause: Docker build cache.** Trial image builds and Trivy left 2.8 GB of cache and about 1 GB of images on the root disk. Rule: after any local build or scan, run `docker builder prune -af && docker image prune -f`. Prefer CI builds.
- **Effect:** the kubelet evicted pods for `ephemeral-storage`, including all of Kyverno. Kyverno is fail-closed, so every API write was rejected, including Argo sync patches.
- **Recovery is slower than expected:** k3s adds a 10% **minimum reclaim**. Once pressure triggers, the taint stays until free space reaches threshold + 10% (18% here), then about 5 more minutes.
- **Watch:** keep root-disk use under 70%. The watchers now abort above 80–90%.

### The startup heal never ran: the Codespace's devcontainer config is captured at creation (found 2026-11-18)
- The Codespace restarted unexpectedly at 13:06 UTC. `/tmp` was emptied, which took the registry caches and the image store with it. Docker re-created `/tmp/difme-containerd` with `/tmp`'s default ACL, so 44 pods failed with `exec ...: permission denied`, Kyverno among them, and the cluster was blocked.
- `postStartCommand` (`ci/image-disk.sh heal`) did not run. `/workspaces/.codespaces/.persistedshare/repo_devcontainer.json` holds the config from creation time, which predates the hook, and a Codespace only re-reads `devcontainer.json` on **Rebuild container**.
- **Until the Codespace is rebuilt** (which also recreates the cluster), run `ci/cs.sh bg heal 'bash ci/image-disk.sh heal'` after any restart. Check with `uptime` and `getfacl -p /tmp/difme-containerd | grep default`.
- After a restart, image pulls come from the internet again (the caches lived on `/tmp`), so recovery takes about 15 min.

### The Codespaces host runs earlyoom: the real memory ceiling is ~90% of 16 GB (found 2026-11-18)
- **Symptom:** containers exit with SIGTERM (exit 143, or a "clean shutdown") about 8–10 s after start. The kubelet, containerd and Kubernetes events give no reason, and there are no probes.
  - Hit: the Argo CD application controller (restart loop for hours) and TigerBeetle (the largest process, about 2.1 GiB allocated at start).
  - The earlier Argo CD reinstall and the Codespace rebuild only helped while memory was lower.
- **Found with the kernel signal tracepoint**, as root in the Codespace:
  `echo 'sig==15' > /sys/kernel/tracing/events/signal/signal_generate/filter; echo 1 > .../enable`, then read `/sys/kernel/tracing/trace`. It shows `earlyoom-689 ... signal_generate: sig=15 comm=tigerbeetle`.
- **What earlyoom is:** it runs on the host VM, not in the Codespace container, so it is not visible in `ps` and not configurable from here. When available memory drops below about 10%, it SIGTERMs the process with the highest `oom_score`. That score is RSS share plus the `oom_score_adj` Kubernetes sets from the pod's QoS.
- **Consequences:**
  - The usable budget is about 14 GB used, not 16 GB.
  - Large processes that allocate at startup (TigerBeetle, JVMs) are killed first.
  - Lower memory *requests* raise a pod's `oom_score_adj`, which makes it a likelier victim.
- **Check memory headroom before** installing a profile or starting a load test. `free -m` "available" must stay above about 2 GB.

### Tier 1 memory: zswap + swapfile + kubelet LimitedSwap (measured 2026-11-18)
- **Setup:**
  - `ci/image-disk.sh swap`, run on every start through `heal`: 16 GiB swapfile on `/tmp`; zswap with zstd, zsmalloc, pool cap 25%.
  - `kubelet-difme.conf`: `failSwapOn: false`, `memorySwap.swapBehavior: LimitedSwap` (Kubernetes 1.32, cgroup v2).
  - The Codespace container is privileged, so zswap parameters and swapon work from inside it.
- **Result** with core and streaming fully up:

| | Before Tier 1 | After Tier 1 |
|---|---|---|
| Available RAM | 2.4 GB | **5.3 GB** |
| Swap in use | none | 2.8 GB |
| Held in the zswap pool | — | 2,656 MiB of pages in **155 MiB** of RAM (≈17:1; idle JVM/Go heaps are mostly empty pages) |
| Written to the disk swapfile | — | 135 MiB |

- **Why it matters:** the host's earlyoom only fires when RAM *and* swap are both below ~10%, so the effective ceiling rises by the swap headroom.
- **Check zswap:** `mount -t debugfs none /sys/kernel/debug`, then read `/sys/kernel/debug/zswap/{pool_total_size,stored_pages,written_back_pages}`.

### Tier 2: low-footprint JVM profile for control-plane JVMs (measured 2026-11-19)
- **Problem:** with the heap capped, a Java operator still had about 150 Mi of non-heap memory: JIT compilers and code cache, metaspace, thread stacks, and glibc malloc arenas (up to 8 per core).
- **Profile** for JVMs that are not on a hot path:
  `-XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:ReservedCodeCacheSize=24m -XX:MaxMetaspaceSize=96m -Xss256k`, plus env `MALLOC_ARENA_MAX=2`.
  - SerialGC: no G1 remembered sets and no parallel GC threads.
  - `TieredStopAtLevel=1`: only the small C1 compiler.
- **Flink operator (Java 17):**

| Container | Before | After | Change |
|---|---|---|---|
| operator | 369 Mi | 204 Mi | −45% |
| webhook | 218 Mi | 88 Mi | −60% |

- **Also applied to:** the Strimzi cluster operator (`extraEnvs` JAVA_OPTS), the topic operator (`jvmOptions."-XX"`) and Apicurio (`JAVA_OPTS_APPEND`).
- **Data-path JVMs** (Kafka broker, Connect, our Quarkus services) keep G1 and full JIT and only get `MALLOC_ARENA_MAX=2`. Our services already use compact object headers, the Java 25 AOT cache and 512k stacks.
- **TigerBeetle:** 0.16.78 exposes its big static allocations as start flags (`--memory-lsm-compaction`, `--limit-pipeline-requests`, `--cache-grid`; `--development` uses the minimums). No custom build is needed. Measure with a throwaway instance before changing the live one.
- **Gotchas found while rolling the profile out (2026-11-19):**
  - **Images whose launcher already picks a GC** (UBI `run-java`, e.g. Apicurio): appending `-XX:+UseSerialGC` gives two GCs and the JVM refuses to start ("Error occurred during initialization of VM"). Set `GC_CONTAINER_OPTIONS=-XX:+UseSerialGC` instead.
  - **Flink operator chart:** the webhook's env goes under `operatorPod.webhook.container.env`, not `webhook.container.env`.
  - **Measured so far:**

| Container | Before | After |
|---|---|---|
| Strimzi cluster operator | 270 Mi | 204 Mi |
| topic operator | 203 Mi | 159 Mi |
| Flink operator | 369 Mi | 204 Mi |
| Flink webhook | 218 Mi | 88 Mi |

  - **TigerBeetle in a plain `docker run`** needs `--security-opt seccomp=unconfined`. Docker's default seccomp profile blocks io_uring ("io_uring is not available"). The k3d node is privileged, so the in-cluster TigerBeetle is unaffected.


### TigerBeetle memory: what the flags do, and zswap (measured 2026-11-19 on a throwaway 0.16.78 instance)
- **RSS by flag set:**

| Flags | RSS |
|---|---|
| Cluster flags | 2.12 GiB |
| `--limit-pipeline-requests=0` | 2.02 GiB |
| … plus `--cache-grid=64MiB` | 1.92 GiB |
| `--development` (32 KiB requests, minimal caches) | 1.45 GiB |
| `--memory-lsm-compaction` | no measurable effect |

- **Model:** most of the static allocation is LSM table memory, sized by the maximum batch (request size) × 32 compaction ops across all trees. `--limit-request` at start is the production-safe lever; it is being measured.
- **With zswap on (Tier 1):** the live TigerBeetle shows **~48 Mi resident** at idle. Its untouched static buffers sit compressed in zswap. Under heavy load they are touched and decompressed again, so a smaller batch size still helps the hot path.
- **Throwaway runs** need `docker run --security-opt seccomp=unconfined` (io_uring). Clean up the image afterwards so the root disk doesn't grow.

### ysql_bench aborts silently on serialization failures
- **Symptom:** a SERIALIZABLE multi-statement script under concurrency ends with `Run was aborted; the above results are incomplete` and no error text. pgbench 15 aborts a client on the first serialization failure.
- **Fix:** add `--max-tries=10 --failures-detailed`. Add `-r` for per-statement latency.

### Kubernetes service-link env collided with flagd's own config: every payment waited 500 ms (found 2026-11-19)
- **Symptom:** a fixed ~520 ms per payment, even one request at a time with no concurrency. Load tests showed p50 ~550 ms at only 15 req/s and limiter shedding.
- **Cause:**
  - Kubernetes injects `<SERVICE>_PORT=tcp://<ip>:<port>` for every Service in the namespace. For the `flagd` Service that is `FLAGD_PORT=tcp://…:8013`, and flagd reads `FLAGD_*` env as its own config.
  - flagd therefore served on a random port (`Flag IResolver listening at [::]:43015`), and :8013 refused connections.
  - cmd-svc used flagd's default **RPC** resolver: one remote call per flag lookup with a 500 ms deadline, paid in full on every payment.
- **Fix:**
  - flagd: `enableServiceLinks: false` and explicit `--port/--sync-port/--ofrep-port`.
  - cmd-svc: the **in-process** resolver (flags sync on :8015 and are evaluated locally in µs), which is what the code comment always claimed.
- **How it was found:** sequential `curl` timings from an in-cluster pod (constant ~520 ms), then `curl` to flagd:8013 (exit 7, connection refused), then flagd's own startup log.
- **Rule:**
  - Any image that reads `<NAME>_*` env (flagd, many Kafka/Redis images) must run with `enableServiceLinks: false` when a Service of the same name exists.
  - Feature-flag lookups on a hot path must be in-process.

### Codespace idle stop and automatic recovery (2026-11-19, 02:17–07:56 IST)
- **What happened:** with no session talking to it, the Codespace stopped after its 60-minute idle timeout. The next SSH call started it again.
- **Since the rebuild, the restart heals itself:** `postStartCommand` re-creates the swapfile and zswap and clears `/tmp`'s default ACL. The cluster came back on its own in about 15 min of image pulls, with no permission errors.
- **Long jobs and the idle timeout:** `ci/bg.sh` now reads the keep-alive token from the **`GH_TOKEN` Codespaces secret** in `/workspaces/.codespaces/shared/.env` (SSH sessions don't load it), so jobs report "with keep-alive" and stay up through the idle timeout.
- **Anything kept in `/tmp` is gone after a restart.** Re-upload helper scripts before re-running.

### After a Codespace restart the k3d node can get a new IP, and Cilium half-breaks (found 2026-11-19)
- **Symptom:** 14 pods crash-loop and don't recover in 20 min.
  - DNS resolves, and Postgres connects.
  - YugabyteDB, Temporal and cmd-svc are unreachable.
  - The Kafka broker can't reach its own headless name.
- **Cause:**
  - Docker gave `k3d-difme-server-0` 172.18.0.3 instead of .2.
  - Cilium logged `endpoint sync cannot take ownership of CEP that is not local ... pod's hostIP "172.18.0.2", cilium nodeIP "172.18.0.3"`, and kept stale endpoint state.
- **Fix:** restart `ds/cilium` and `deploy/cilium-operator`, then delete pods whose `status.hostIP` is not the node's InternalIP. Connectivity came back at once.
- **Now automatic:** `ci/image-disk.sh heal` (postStartCommand) calls `refresh_network` once the node is Ready.
- **Check by hand:** `nc -z` from a busybox pod to `yb-tservers.database-tier:5433`, `temporal-frontend.temporal:7233` and `difme-kafka-bootstrap.streaming:9092`.

## Runtime on a plain VM (free-tier arm64 cloud VM) — 2026-11-20
- Bootstrap: `curl -fsSL https://raw.githubusercontent.com/pratikmohanty1994-ui/difme/main/ci/vm-bootstrap.sh | bash`, then log in again (docker group), then `make cluster && make up PROFILE=core`.
- Persistent disk: `DIFME_IMAGE_DIR=/var/lib/difme/containerd` and `DIFME_SWAP_FILE=/var/lib/difme/swap` (set in `/etc/profile.d/difme.sh` and in `~/.bashrc` for non-interactive SSH). The Makefile and `ci/image-disk.sh` honour both.
- There is no host earlyoom (that was a Codespaces host feature), so the full 24 GB is usable; zswap and swap still apply.
- Every image must be multi-arch: check new third-party pins with `python3 ci/archcheck.py <file of image refs>` before adding them.


### Back-office nginx pods crash-looped on the read-only root filesystem (cluster-verify 2026-11-20)
- **Symptom:** all six back-office pods (shell + 5 remotes) in CrashLoopBackOff: `mkdir() "/tmp/proxy_temp" failed (30: Read-only file system)`.
- **Root cause:** Kyverno `mutate-defaults` sets `readOnlyRootFilesystem: true` on every container; nginx-unprivileged keeps its pid and temp paths in `/tmp`.
- **Fix:** one kustomize patch in `back-office-ui/backoffice-web/kustomization.yaml` gives every Deployment a 16 Mi disk-backed `/tmp`.
- **Rule:** any new image (nginx, JVM, Node) needs its writable paths mounted before it ships; check the image's temp, cache and pid directories.

### Istio ambient on Cilium in k3d: istio-cni never ready (2026-11-20)
- **Symptom:** istio-cni-node readiness 503 for 50 min while its agent was enrolling pods normally.
- **Evidence:** node listing showed only `/etc/cni/net.d/05-cilium.conflist`; `/var/lib/rancher/k3s/agent/etc/cni/net.d` empty.
- **Causes:** (1) `global.platform: k3d` points istio-cni at the k3s CNI dirs, but with flannel disabled Cilium writes to the defaults; (2) Cilium's default `cni.exclusive: true` removes other plugins' entries from its conflist, so istio-cni's chained plugin kept disappearing.
- **Fix:** chart-default CNI dirs for istio-cni; Cilium `cni: { exclusive: false }`.

# How we work: fast feedback loop

1. **Verify before pushing.**
   - `make check AREA=<core|flink|backoffice|deploy|api|tla>` runs in the Codespace in seconds to about a minute.
   - For manifests, also run a server dry run: `kustomize build … | kubectl apply --server-side --force-conflicts --dry-run=server -f -`.
   - CI confirms; it should not discover.
2. **Look things up before writing.** For any API, flag, chart key or image tag you aren't sure about, check the docs, `helm show values` or the registry first.
3. **Time-box infrastructure experiments to two attempts**, then take the documented configuration and record the deviation in an ADR.
4. **Wait on conditions, not timers:** `kubectl wait`, `rollout status`, or `until …; do sleep; done` inside one remote call.
5. **Batch fixes into one push.** Never push one-line fixes one by one.
6. **Record every multi-attempt problem here** (symptom → cause → fix → prevention).
7. **Never sit idle.** While a run or sync is in progress, work on the next item.
8. **Know the expected duration** of every step and report an overrun before being asked; give watchers deadlines.
9. **Commit before switching branches;** an uncommitted edit once travelled into an unrelated branch.
10. **Owner answers go into [owner-decisions.md](owner-decisions.md)** the same day, never only into a chat.
11. **Progress survives stoppages:** push each change to its `wip-*` branch immediately and update the PROGRESS LOG in `docs/status.md` on `main` after every step; run logs stream live and remain even if a runner dies.
12. **Stash untracked files before switching branches** (`git stash -u`). A `git add -A` on another branch sweeps them into an unrelated commit; a stray `Bounded.java` landed on main that way and triggered a full image rebuild (2026-11-20).
13. **cluster-verify fails fast:** a profile stops waiting when a pod crash-loops (≥ 5 restarts, still failing 3 min later) or sits in an image/config error for 4 min, and prints `FAILFAST <profile> after Ns: <pods>` plus the diagnostics. Read `CONVERGED / FAILFAST / TIMEOUT / SYNC FAILURE` per profile.
14. **Argo CD follows `main` live.** A merge to `main` while a cluster-verify run on `main` is in flight changes what that run installs. Hold merges that touch manifests or images until A/B or verification runs on `main` finish (2026-11-20).
15. **Commits carry no assistant trailers** (owner rule, it outranks any tool default): author `pratikmohanty1294 <pratikmohanty1294@users.noreply.github.com>`, plain message.
16. **A lost runner loses the whole log.** Twice on core,streaming,lakehouse (2026-11-20). cluster-verify now makes the runner agent OOM-exempt with CPU/IO priority (`Guard the runner agent` step), so pods are what get squeezed.
17. **Check a readiness path exists in the upstream version before blaming the app.** formio 4.11 OSS has no `/health`; the probe hit the alias handler and got 400 for a day of digging (2026-11-20).
18. **Parse every edited YAML before pushing** (a scripted edit put a comment inside a flow mapping, 2026-11-20). `verify` now parses all of deploy/**/*.yaml.
19. **Spend Actions and Codespaces like a budget** (2026-11-21, after the old account lost Actions on 2026-11-20 and its
    Codespace on 2026-11-19). The repository is public, so hosted-runner minutes cost nothing, but bursts of long,
    CPU-saturating jobs are what preceded "owner invocation blocked" (~30-job full image rebuilds on every merge, five
    3-hour cluster-verify runs in parallel). So:
    - **Images in waves:** `images` dispatch input `only` (e.g. `scheme` first as a pipeline canary, then `core`, then the
      rest, Hyperswitch alone). Pushes build only groups whose sources changed since that group's last green build
      (`ci/image-changes.py`); a pipeline edit no longer rebuilds everything. Runs queue, never cancel each other.
    - **Push to `main` with `[skip ci]`** when the change can't affect a run (docs, or while a wave is still building)
      and check it locally instead; batch fixes (rule 5).
    - **One cluster-verify at a time** (workflow concurrency) and only after the images it needs are green.
    - **Codespaces (free plan: 120 core-hours and 15 GB-month storage a month):** the 4-core devcontainer burns 4
      core-hours per hour, so 30 hours a month, and a stopped 32 GB Codespace kept all month alone uses ~32 GB-month, over
      the free storage. Use it only for interactive cluster work, set the idle timeout to 30 min, stop it when done and
      delete it when the next session is days away; no prebuilds. Builds belong in Actions, the long-running cluster on the
      runtime VM.

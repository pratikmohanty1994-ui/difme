#!/usr/bin/env python3
"""Decide which image groups images.yml builds (writes <key>=true|false to $GITHUB_OUTPUT).

Per group, not per run: a group is rebuilt only when its sources changed since the last images run in which all of
that group's jobs succeeded. Before 2026-11-21 one failed or cancelled job anywhere made the next push rebuild every
image (~40 jobs, two of them multi-hour Rust builds); full rebuilds on every merge were the bulk of the usage that got
the old account's Actions disabled (2026-11-20). An edit to the image pipeline itself no longer rebuilds everything:
dispatch with `only: all` when that is really wanted.

  ONLY=""            changed groups only (push, or dispatch without input)
  ONLY="all"         every group
  ONLY="core,pwa"    exactly these groups

Needs GH_TOKEN with actions:read, GITHUB_REPOSITORY, GITHUB_REF_NAME, GITHUB_RUN_ID; run from the checkout (full depth).
"""
import json, os, re, subprocess, sys

# key, job id in images.yml (its -manifest job counts too), source paths
GROUPS = [
    ("core", "core", r"^(services/core/|api/proto/|api/openapi/|verticals/)"),
    ("backoffice", "backoffice", r"^(backoffice/|vendor/formio/js/)"),
    ("pwa", "pwa", r"^pwa/"),
    ("flink", "flink-jobs", r"^(analytics/flink-jobs/|processes/dmn/)"),
    ("dbt", "dbt", r"^analytics/dbt/"),
    ("formio", "formio", r"^(vendor/formio/server/|deploy/images/formio/)"),
    ("hub", "quinn-hub", r"^(services/hub/|api/proto/|deploy/images/quinn-hub/)"),
    ("attestation", "attestation-verifier", r"^(services/attestation/|api/proto/|deploy/images/attestation-verifier/)"),
    ("feast", "feast", r"^(ml/feast/|deploy/images/feast/)"),
    ("notary", "notary", r"^(services/notary/|deploy/images/notary/)"),
    ("fraud", "fraud-scorer", r"^(services/fraud-scorer/|ml/fraud/|deploy/images/fraud-scorer/)"),
    ("hsm", "hsm", r"^(services/hsm/|deploy/images/hsm/)"),
    ("cardissuer", "card-issuer", r"^(services/card-issuer/|deploy/images/card-issuer/)"),
    ("scheme", "scheme-sim", r"^(services/scheme-sim/|vendor/moov-iso8583/|deploy/images/scheme-sim/)"),
    ("fineract", "fineract", r"^(vendor/fineract/|deploy/images/fineract/)"),
    ("hyperswitch", "hyperswitch", r"^(vendor/hyperswitch/|deploy/images/hyperswitch/)"),
    ("debezium", "debezium-connect", r"^deploy/images/debezium-connect/"),
    ("veraison", "veraison", r"^deploy/images/veraison/"),
    ("tazama", "tazama", r"^(vendor/tazama/|services/fraud-rules/|deploy/images/tazama/)"),
    ("mojaloop", "mojaloop", r"^(vendor/mojaloop/|deploy/images/mojaloop/)"),
    ("phee", "ph-ee", r"^(vendor/mifos-ph-ee/|vendor/interledger/|services/zeebe-on-fluxnova/|services/fspiop-ilp-models/|deploy/images/mifos-ph-ee/)"),
]


def gh(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def group_ok(jobs, job_id):
    """True when the run has jobs of this group and every one of them succeeded."""
    pat = re.compile(rf"^{re.escape(job_id)}(-manifest)?( \(| /|$)")
    mine = [j for j in jobs if pat.match(j["name"])]
    return bool(mine) and all(j["conclusion"] == "success" for j in mine)


def bases(repo, branch, this_run, wanted):
    """Head sha of the newest completed run per group in which that group fully succeeded."""
    found = {}
    runs = gh(f"repos/{repo}/actions/workflows/images.yml/runs?branch={branch}&status=completed&per_page=40")
    for run in runs.get("workflow_runs", []):
        if str(run["id"]) == str(this_run):
            continue
        jobs = gh(f"repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100&filter=latest")["jobs"]
        for key, job_id, _ in GROUPS:
            if key in wanted and key not in found and group_ok(jobs, job_id):
                found[key] = run["head_sha"]
        if len(found) == len(wanted):
            break
    return found


def main():
    only = os.environ.get("ONLY", "").strip()
    keys = [k for k, _, _ in GROUPS]
    if only == "all":
        build = {k: True for k in keys}
    elif only:
        asked = {x.strip() for x in only.split(",") if x.strip()}
        unknown = asked - set(keys)
        if unknown:
            sys.exit(f"unknown group(s): {', '.join(sorted(unknown))}; known: {', '.join(keys)}")
        build = {k: k in asked for k in keys}
    else:
        found = bases(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_REF_NAME"],
                      os.environ.get("GITHUB_RUN_ID", ""), set(keys))
        build = {}
        for key, _, rx in GROUPS:
            base = found.get(key)
            if not base or subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"]).returncode != 0:
                build[key] = True
                print(f"{key}: no green build on record -> build")
                continue
            files = subprocess.check_output(["git", "diff", "--name-only", base, "HEAD"], text=True).split()
            hit = [f for f in files if re.match(rx, f)]
            build[key] = bool(hit)
            print(f"{key}: base {base[:10]}, {len(hit)} changed file(s) -> {'build' if hit else 'skip'}")
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/stdout"), "a") as out:
        for k in keys:
            out.write(f"{k}={'true' if build[k] else 'false'}\n")
    print("build:", " ".join(k for k in keys if build[k]) or "nothing")


if __name__ == "__main__":
    main()

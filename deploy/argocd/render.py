#!/usr/bin/env python3
"""Render deploy/argocd/catalog.yaml into Argo CD Applications and profile lists.

Usage: python deploy/argocd/render.py [--check]
--check exits non-zero if the generated files are out of date (used in CI).
"""
import re
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
REPO = "https://github.com/pratikmohanty1994-ui/difme.git"
APPS = ROOT / "deploy/argocd/apps"
PROFILES = ROOT / "deploy/profiles"
# Composite profiles: `make up PROFILE=all` etc.
COMPOSITE = {
    "all": None,  # every component
    "payments": ["core", "streaming", "observability"],
}


IGNORE = {
    "policy-controller": [
        {"group": "admissionregistration.k8s.io", "kind": "MutatingWebhookConfiguration", "jqPathExpressions": [".webhooks[]?.clientConfig.caBundle", ".webhooks[]?.objectSelector", ".webhooks[]?.namespaceSelector"]},
        {"group": "admissionregistration.k8s.io", "kind": "ValidatingWebhookConfiguration", "jqPathExpressions": [".webhooks[]?.clientConfig.caBundle", ".webhooks[]?.objectSelector", ".webhooks[]?.namespaceSelector"]},
    ],
    # No ignore rules for "policies": with RespectIgnoreDifferences, Argo CD re-applied the OLD live .spec.rules that
    # Kyverno's webhook touches, silently dropping changes (found live). Server-side diff already handles defaults.
    # istiod owns these at runtime: it injects its CA into the webhooks and switches the default validator's
    # failurePolicy to Fail once it is serving (Istio's documented Argo CD setup). Without the rules both apps stay
    # OutOfSync and self-heal fights istiod in a loop (cluster-verify 44718018139: argocd controller ~350m CPU).
    "istio-base": [
        {"group": "admissionregistration.k8s.io", "kind": "ValidatingWebhookConfiguration", "jqPathExpressions": [".webhooks[]?.failurePolicy", ".webhooks[]?.clientConfig.caBundle"]},
    ],
    "istiod": [
        {"group": "admissionregistration.k8s.io", "kind": "ValidatingWebhookConfiguration", "jqPathExpressions": [".webhooks[]?.failurePolicy", ".webhooks[]?.clientConfig.caBundle"]},
        {"group": "admissionregistration.k8s.io", "kind": "MutatingWebhookConfiguration", "jqPathExpressions": [".webhooks[]?.clientConfig.caBundle"]},
    ],
    # ADR-029 scale-to-zero: KEDA owns these Deployments' replica counts (deploy/platform/*/idle-scaling); declared
    # replicas would make Argo CD and KEDA reset each other (as with rehydration-svc and its HPA, found live).
    "trino": [{"group": "apps", "kind": "Deployment", "name": "trino-coordinator", "jsonPointers": ["/spec/replicas"]}],
    "superset": [{"group": "apps", "kind": "Deployment", "name": "superset", "jsonPointers": ["/spec/replicas"]},
                 {"group": "apps", "kind": "Deployment", "name": "superset-worker", "jsonPointers": ["/spec/replicas"]}],
    "mlflow": [{"group": "apps", "kind": "Deployment", "name": "mlflow", "jsonPointers": ["/spec/replicas"]}],
    "envoy-gateway": [
        {"group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "jqPathExpressions": [".rules"]},
        {"group": "rbac.authorization.k8s.io", "kind": "ClusterRoleBinding", "jqPathExpressions": [".subjects"]},
    ],
}


def application(c: dict) -> dict:
    base = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {
            "name": c["name"],
            "namespace": "argocd",
            # label values allow only [A-Za-z0-9._-]: "4.1/ADR-010" -> "4.1_ADR-010" (an invalid label made Argo CD
            # reject the whole Application, so Keycloak never deployed in cluster runs 2 and 3)
            "labels": {"difme/profile": c["profile"], "difme/pdf-section": re.sub(r"[^A-Za-z0-9._-]", "_", str(c["pdf"])).strip("_.-") or "none"},
            "annotations": {"argocd.argoproj.io/sync-wave": str(c["wave"])},
            "finalizers": ["resources-finalizer.argocd.argoproj.io"],
        },
        "spec": {
            "project": "difme",
            "destination": {"server": "https://kubernetes.default.svc", "namespace": c["ns"]},
            "syncPolicy": {
                "automated": {"prune": True, "selfHeal": True},
                "syncOptions": ["CreateNamespace=true", "ServerSideApply=true"],
                "retry": {"limit": 5, "backoff": {"duration": "10s", "factor": 2, "maxDuration": "3m"}},
            },
        },
    }
    # Fields owned by controllers/webhooks at runtime (verified on the live cluster) are not drift.
    ignore = IGNORE.get(c["name"])
    if ignore:
        base["spec"]["ignoreDifferences"] = ignore
        base["spec"]["syncPolicy"]["syncOptions"].append("RespectIgnoreDifferences=true")
    local = f"deploy/platform/{c['ns']}/{c['name']}"
    if c["kind"] == "helm":
        base["spec"]["sources"] = [
            {
                "repoURL": c["repo"],
                "chart": c["chart"],
                "targetRevision": c["version"],
                "helm": {"releaseName": c["name"], "valueFiles": [f"$values/{local}/values.yaml"]},
            },
            {"repoURL": REPO, "targetRevision": "main", "ref": "values"},
        ]
    else:
        base["spec"]["source"] = {"repoURL": REPO, "targetRevision": "main", "path": local}
    return base


def render() -> dict[pathlib.Path, str]:
    catalog = yaml.safe_load((ROOT / "deploy/argocd/catalog.yaml").read_text(encoding="utf-8"))["components"]
    out: dict[pathlib.Path, str] = {}
    profiles: dict[str, list[str]] = {}
    for c in catalog:
        out[APPS / f"{c['name']}.yaml"] = yaml.safe_dump(application(c), sort_keys=False)
        profiles.setdefault(c["profile"], []).append(c["name"])
    for name, members in COMPOSITE.items():
        apps = [c["name"] for c in catalog if c["profile"] != "base"] if members is None else [
            a for p in members for a in profiles.get(p, [])
        ]
        profiles[name] = apps
    for name, apps in profiles.items():
        out[PROFILES / f"{name}.txt"] = f"# generated by deploy/argocd/render.py\n" + "\n".join(apps) + "\n"
    return out


def main() -> int:
    files = render()
    if "--check" in sys.argv:
        stale = [p for p, body in files.items() if not p.exists() or p.read_text(encoding="utf-8") != body]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)}")
        return 1 if stale else 0
    APPS.mkdir(parents=True, exist_ok=True)
    PROFILES.mkdir(parents=True, exist_ok=True)
    for p, body in files.items():
        p.write_text(body, encoding="utf-8", newline="\n")
    print(f"rendered {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Expand core-services/services.yaml into Deployments + Services, split by profile group:
   core      -> deploy/platform/core-platform/core-services/generated.yaml   (profile: core)
   streaming -> deploy/platform/core-platform/stream-services/generated.yaml (profile: streaming; needs Kafka)
Run by `make check AREA=deploy`; CI fails if the generated files are stale."""
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "deploy/platform/core-platform/core-services/services.yaml"
OUT = {
    "core": ROOT / "deploy/platform/core-platform/core-services/generated.yaml",
    "streaming": ROOT / "deploy/platform/core-platform/stream-services/generated.yaml",
}


def manifests(s: dict) -> list[dict]:
    labels = {"app": s["name"], "version": "stable", "difme/team": s["team"], "business.metric": s["metric"]}
    env = [
        {"name": "QUARKUS_HTTP_PORT", "value": str(s["port"])},
        {"name": "QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://alloy.observability.svc:4317"},
        {"name": "QUARKUS_OTEL_SDK_DISABLED", "value": "true"},  # enabled by the observability overlay
        {"name": "FLAGD_HOST", "value": "flagd.core-platform.svc"},
    ]
    # Root filesystem is read-only (policies/kyverno/mutate-defaults.yaml); Quarkus/Vert.x needs a small writable /tmp
    # for its file cache (found live). Disk-backed so it doesn't count against the memory limit.
    volumes = [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}]
    mounts = [{"name": "tmp", "mountPath": "/tmp"}]
    container = {
        "name": "app",
        "image": f"ghcr.io/pratikmohanty1994-ui/{s['image']}:0.1.0",
        "ports": [{"name": "http", "containerPort": s["port"]}, {"name": "grpc", "containerPort": 9000}],
        "env": env,
        "readinessProbe": {"httpGet": {"path": "/q/health/ready", "port": s["port"]}, "periodSeconds": 10},
        "livenessProbe": {"httpGet": {"path": "/q/health/live", "port": s["port"]}, "initialDelaySeconds": 30},
        "resources": {"requests": {"cpu": s["cpu"], "memory": s["mem"]}, "limits": {"memory": s["mem"]}},
    }
    # Evidence custody (decided 2026-11-20): with the security profile, the operator seal is signed by OpenBao transit
    # and the notary witnesses. The settings arrive in an optional ConfigMap that only the security profile creates
    # (deploy/platform/core-platform/exchange-evidence); without it the service keeps local dev keys. The projected
    # token (audience "vault") is what the exchange presents to OpenBao's Kubernetes auth.
    if s.get("evidence"):
        container.setdefault("envFrom", []).append({"configMapRef": {"name": "exchange-evidence", "optional": True}})
        volumes.append({"name": "openbao-sa", "projected": {"sources": [{"serviceAccountToken": {
            "audience": "vault", "expirationSeconds": 3600, "path": "token"}}]}})
        mounts.append({"name": "openbao-sa", "mountPath": "/var/run/secrets/openbao-sa", "readOnly": True})
    # Durable exchange state (StateStore, 2026-11-21): latest version of each record in YugabyteDB, schema "exchange".
    if s.get("store"):
        env.append({"name": "DIFME_EXCHANGE_STORE_URL", "value": "jdbc:postgresql://yb-tservers.database-tier.svc:5433/difme"})
    # Real rails (2026-11-21): the rails profile ships ConfigMap exchange-rails (payment hub URL, partner cards on file).
    # Without it the exchange keeps its simulated rails, so the core profile works on its own.
    if s.get("rails"):
        container.setdefault("envFrom", []).append({"configMapRef": {"name": "exchange-rails", "optional": True}})
        # D3: PH-EE client credentials and Fluxnova login for escrow movements through PH-EE (PhEePaymentHub)
        container["envFrom"].append({"secretRef": {"name": "exchange-phee", "optional": True}})
    # Loan origination (ADR-025): Fineract/Tazama endpoints and the Keycloak client, shipped by the rails profile.
    if s.get("loans"):
        container.setdefault("envFrom", []).append({"configMapRef": {"name": "loan-origination", "optional": True}})
        container["envFrom"].append({"secretRef": {"name": "loan-origination-oauth", "optional": True}})
    if mounts:
        container["volumeMounts"] = mounts
    # No service-link env (KUBERNETES-style <SVC>_PORT=tcp://...): our services resolve by DNS, and those variables
    # collided with an image's own config once (flagd, 2026-11-19).
    spec = {"serviceAccountName": s["name"], "enableServiceLinks": False, "containers": [container]}
    if volumes:
        spec["volumes"] = volumes
    deploy_spec = {"selector": {"matchLabels": {"app": s["name"]}},
                   "template": {"metadata": {"labels": labels}, "spec": spec}}
    # KEDA owns the replica count of autoscaled services; declaring it here made Argo CD and the HPA reset each
    # other's value in a loop (found live). Same for services behind a canary Rollout (canary-gates, workloadRef with
    # scaleDown): Argo Rollouts scales the Deployment to 0 and Argo CD self-heal put it back to 1, so a fresh pod was
    # started and killed about once a minute (cluster-verify 2026-11-20). Left out, the API default of 1 still applies
    # when the profile has no Rollout. Everyone else runs one replica in the Codespace.
    if not (s.get("autoscaled") or s.get("rollout")):
        deploy_spec = {"replicas": 1, **deploy_spec}
    # Single writer of durable state (StateStore): the old pod stops before the new one starts, so two exchange pods
    # never run their matching and stores side by side during a rollout (a short gap instead of split state).
    if s.get("store"):
        deploy_spec["strategy"] = {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}}
    return [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": s["name"], "labels": {"app": s["name"]}},
         "spec": deploy_spec},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": s["name"], "labels": {"app": s["name"]}},
         "spec": {"selector": {"app": s["name"]}, "ports": [{"name": "http", "port": s["port"]}, {"name": "grpc", "port": 9000}]}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": s["name"]}},
    ]


def main() -> None:
    cm = yaml.safe_load(SRC.read_text(encoding="utf-8"))
    groups: dict[str, list[dict]] = {g: [] for g in OUT}
    for s in yaml.safe_load(cm["data"]["services.yaml"]):
        groups[s.get("group", "core")].extend(manifests(s))
    for g, docs in groups.items():
        OUT[g].parent.mkdir(parents=True, exist_ok=True)
        OUT[g].write_text("# generated by deploy/components/quarkus-service/render.py — edit core-services/services.yaml\n"
                          + yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8", newline="\n")
        print(f"rendered {len(docs) // 3} {g} services")


if __name__ == "__main__":
    main()

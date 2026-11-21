#!/usr/bin/env bash
# Bootstraps Cilium + Argo CD + the app-of-apps root. Everything after this is GitOps.
set -euo pipefail
REPO=${1:-https://github.com/pratikmohanty1994-ui/difme.git}

helm repo add cilium https://helm.cilium.io >/dev/null
helm upgrade --install cilium cilium/cilium -n kube-system --version 1.17.3 \
  -f deploy/platform/kube-system/cilium/values.yaml --wait --timeout 10m

kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argocd --server-side -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.14.11/manifests/install.yaml
kubectl -n argocd rollout status deploy/argocd-server --timeout=300s
# ADR-015: Keycloak is the identity provider; Argo CD's bundled Dex is redundant.
kubectl -n argocd scale deploy argocd-dex-server --replicas=0
# Kustomize dirs pull shared files (flags, Lua scripts, dashboards) from elsewhere in the repo.
kubectl -n argocd patch configmap argocd-cm --type merge --patch-file deploy/bootstrap/argocd-cm-patch.yaml
# Server-side diff (controller-defaulted fields aren't drift) and generous repo/Helm timeouts so large chart
# downloads on slow links don't fail a sync (ADR-012 network I/O).
kubectl -n argocd patch configmap argocd-cmd-params-cm --type merge -p '{"data":{"controller.diff.server.side":"true","controller.repo.server.timeout.seconds":"300","reposerver.parallelism.limit":"2","controller.status.processors":"6","controller.operation.processors":"3","controller.kubectl.parallelism.limit":"4"}}'
kubectl -n argocd set env deploy/argocd-repo-server ARGOCD_EXEC_TIMEOUT=300s ARGOCD_GIT_ATTEMPTS_COUNT=5 >/dev/null
# Tier 2 memory (Go): soft heap limit + earlier GC for the controller. The limit must sit well above the live heap: with
# all 12 profiles (~100 apps) the controller needed ~420 MiB, and a 350 MiB limit made Go collect continuously
# (5.3 cores, node CPU 95%; cluster-verify 2026-11-20, all-at-once run 3). GOGC=75 still keeps the heap tight below it.
kubectl -n argocd set env statefulset/argocd-application-controller GOMEMLIMIT=700MiB GOGC=75 >/dev/null
kubectl -n argocd rollout restart statefulset/argocd-application-controller deploy/argocd-repo-server >/dev/null
# Argo Rollouts lives in its own namespace: its RBAC binds the argo-rollouts/argo-rollouts service account (found live).
kubectl create namespace argo-rollouts --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argo-rollouts --server-side -f https://github.com/argoproj/argo-rollouts/releases/download/v1.8.2/install.yaml

sed "s#__REPO__#$REPO#g" deploy/argocd/project.yaml | kubectl apply -f -
# The base profile is always on: infra layer 11 (namespaces, CRDs, policy, ingress).
for a in $(grep -v '^#' deploy/profiles/base.txt); do kubectl apply -f deploy/argocd/apps/$a.yaml; done
echo "Argo CD admin password: $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)"

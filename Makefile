# DIFME — run from inside a Codespace.
SHELL := /bin/bash
CLUSTER ?= difme
PROFILE ?= core
REPO    ?= https://github.com/pratikmohanty1994-ui/difme.git
APPS     = $(shell cat deploy/profiles/$(PROFILE).txt 2>/dev/null | grep -v '^\#')

.PHONY: help registries prefetch cluster destroy up down status ui verify test build tla lint check
AREA    ?= all
MODULES ?=

check:           ## Fast pre-push checks for one area: make check AREA=core MODULES=cmd-svc
	bash ci/check.sh $(AREA) $(MODULES)

help:            ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n",$$1,$$2}'
	@echo "  Profiles: $$(ls deploy/profiles | sed 's/.txt//' | tr '\n' ' ')"

registries:      ## Pull-through image caches on the Codespace's 118 GB /tmp disk (survive `make destroy`; a Codespace
                 ## restart empties /tmp and they refill from upstream). Keeps ~5 GB off the 32 GB root disk.
	@for r in dockerio=https://registry-1.docker.io ghcr=https://ghcr.io quay=https://quay.io k8s=https://registry.k8s.io; do \
	  name=difme-$${r%%=*}; url=$${r#*=}; \
	  if k3d registry list -o json 2>/dev/null | grep -q "k3d-$$name\""; then echo "registry cache: $$name (exists)"; \
	  else k3d registry create $$name --port 0 --proxy-remote-url $$url -v /tmp/difme-registry/$$name:/var/lib/registry >/dev/null && echo "registry cache: $$name -> $$url (created)"; fi; \
	done

cluster: registries   ## Create the k3d cluster: Cilium, Argo CD, dev secrets (images via local caches)
	@# Image layers go on the 118 GB /tmp disk (ci/image-disk.sh clears /tmp's default ACL, the cause of the earlier
	@# non-root failures). Volumes stay on the root disk. Kubelet image GC (kubelet-difme.conf) still bounds growth.
	bash ci/image-disk.sh prepare
	K3D_FIX_DNS=0 k3d cluster create --config deploy/bootstrap/k3d.yaml 	  --volume $${DIFME_IMAGE_DIR:-/tmp/difme-containerd}:/var/lib/rancher/k3s/agent/containerd@server:* \
	  --volume $(CURDIR)/deploy/bootstrap/k3s-resolv.conf:/etc/difme/resolv.conf@server:* \
	  --volume $(CURDIR)/deploy/bootstrap/kubelet-difme.conf:/var/lib/rancher/k3s/agent/etc/kubelet.conf.d/50-difme.conf@server:*
	bash deploy/bootstrap/install.sh $(REPO)
	bash deploy/bootstrap/dev-secrets.sh

destroy:         ## Delete the cluster
	k3d cluster delete $(CLUSTER)

prefetch:        ## Pre-pull a profile's images (parallel, retried) so pods never wait on the network
	bash ci/prefetch.sh $(PROFILE)

up: prefetch     ## Enable a profile wave by wave, e.g. make up PROFILE=streaming (images prefetched first)
	bash ci/up.sh $(PROFILE)
	@echo "Argo CD is syncing. Check with: make status"

down:            ## Disable a profile and free resources
	@for a in $(APPS); do kubectl -n argocd delete application $$a --ignore-not-found; done

status:          ## Argo CD app health plus pod memory
	@kubectl -n argocd get applications -o custom-columns=APP:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status
	@kubectl top nodes 2>/dev/null || true

ui:              ## Port-forward Argo CD, Grafana and Temporal UIs
	kubectl -n argocd port-forward svc/argocd-server 8080:443 & \
	kubectl -n observability port-forward svc/grafana 3000:80 & \
	kubectl -n temporal port-forward svc/temporal-web 8233:8080 & wait

build:           ## Build all services
	mvn -q -B -f services/core/pom.xml package -DskipTests
	@# Rust components (Platform section B) build once their source exists.
	@for d in services/hub services/attestation services/notary edge/core; do if [ -d $$d ]; then (cd $$d && cargo build --release) || exit 1; else echo "skip $$d (not written yet)"; fi; done
	cd backoffice && pnpm install --frozen-lockfile && pnpm turbo build

test:            ## Unit plus contract tests
	mvn -q -B -f services/core/pom.xml verify
	@for d in services/hub services/attestation services/notary edge/core; do if [ -d $$d ]; then (cd $$d && cargo test) || exit 1; else echo "skip $$d (not written yet)"; fi; done
	cd backoffice && pnpm turbo test

tla:             ## Model-check every TLA+ spec
	bash specs/tla/check.sh

lint:            ## Semgrep, Buf, Spectral, AsyncAPI
	semgrep --config policies/semgrep --error services/
	cd api/proto && buf lint && buf breaking --against '.git#branch=main,subdir=api/proto'
	spectral lint api/openapi/*.yaml
	asyncapi validate api/asyncapi/difme.asyncapi.yaml

verify: lint tla test   ## Run every local quality gate

# Licence scan of every third-party package (owner rule: free and open source only). Report: docs/knowledge-base/licence-scan.md
licence-scan:
	python3 ci/licence-scan.py --report docs/knowledge-base/licence-scan.md

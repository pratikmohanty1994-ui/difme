# Deployment scenarios A–D (ADR-028)

DIFME runs the same GitOps tree in four topologies. Each scenario (or each site of one) is a Kustomize overlay of
the generated Argo CD Applications, produced by `deploy/overlays/render.py` from `deploy/overlays/scenarios.yaml`.
The verify workflow checks that the overlays are current and that each one builds. Cloud machines come from the
OpenTofu roots in `infra/` (OpenTofu, MPL-2.0; Terraform is BSL).

| Scenario | Overlay | Machines | Load balancing / DNS |
|---|---|---|---|
| A on-premises | `scenario-a-onprem` (all components) | RKE2 with the CIS profile (`deploy/fleet/rke2-config.yaml`) on bare metal or VMs; cloud-init from `infra/modules/rke2-node` | MetalLB BGP to the site router (`components/metallb-bgp`); external-dns through RFC 2136 to the site's DNS |
| B cloud | `scenario-b-cloud` (all components, no MetalLB) | `infra/scenarios/b-cloud`: 3 servers + agents on Hetzner Cloud, API load balancer, private network | cloud load balancer; RFC 2136 DNS |
| C hybrid | `scenario-c-hybrid/onprem` + `scenario-c-hybrid/cloud` | on-premises as A; cloud from `infra/scenarios/c-hybrid-cloud` (B's cluster + WireGuard gateway) | as A / as B |
| D QUIC proxy chain | `scenario-d-quic-chain` (core, hub, identity) | as A, plus a relay host at each branch/site | as A |

Every real cluster gets the full eBPF data path (`values/cilium-full-ebpf.yaml`: kube-proxy replacement, eBPF host
routing). `api.difme.internal` must resolve to the API load balancer on every node.

## C: what runs where, and what crosses

The on-premises site keeps every stateful and regulated tier: ledger and core services, card security (hsm in the
TEE, ACS, card-issuer), CBS (Fineract), payment rails, fraud (Tazama), streaming, lakehouse, ML and identity
(Keycloak, OpenBao, SPIRE, Trustee). Cardholder data and keys never leave it. The cloud site runs the stateless edge
tier: the QUIC hub for edge devices, the back office and the DiscountAI PWA, ingress, and its own observability stack.

Three Services cross, from on-premises to the cloud:

| Service | Used by (cloud) |
|---|---|
| `security/keycloak` :8080 | back office and PWA logins, token validation |
| `security/attestation-verifier` :8443 | QUIC hub (device attestation) |
| `core-platform/quarkus-cmd-svc` :8080/:9000 | QUIC hub (payment commands over gRPC) |

They cross as Cilium ClusterMesh global services (Cilium 1.17 has no MCS-API, and global services can't be
headless). The on-premises overlay adds `<name>-x`, a ClusterIP copy of the Service, marked global and shared. The
cloud overlay adds a selector-less `<name>-x`, marked global and not shared, whose endpoints come from on-premises,
plus an ExternalName `<name>` pointing at it, so cloud workloads keep the DNS names they already use. No original
manifest changes.

ClusterMesh prerequisites:
- the two clusters share one Cilium CA;
- pod ranges don't overlap (on-premises 10.32.0.0/12, cloud 10.48.0.0/12, in `values/cilium-mesh-*.yaml`);
- nodes and pods reach each other through the WireGuard tunnel (cloud gateway from `infra/scenarios/c-hybrid-cloud`,
  routes for the on-premises ranges in the cloud network; the site router routes 10.10.0.0/16 and 10.48.0.0/12 back);
- `clustermesh.difme-<site>.internal` resolves to the other site's clustermesh-apiserver load balancer.

Istio ambient policies name SPIFFE identities of their own cluster, so cross-site calls are authorised by Keycloak
tokens (the services already require them) and encrypted twice: by the WireGuard tunnel and by Cilium's WireGuard
pod-to-pod encryption.

## D: QUIC proxy chain

Edge devices on a branch network connect to a local QUIC relay (`services/hub/quic-relay`, shipped in the hub image
as a second binary), which keeps one upstream QUIC connection to the cluster's hub and forwards device streams over
it. Configuration: `RELAY_UPSTREAM` (hub host:port), `RELAY_UPSTREAM_NAME`, `RELAY_UPSTREAM_CA` (PEM CA of the hub's
certificate), and `RELAY_TLS_CERT` / `RELAY_TLS_KEY` for the relay's own listener. The cluster side is
`scenario-d-quic-chain`: base, security, core, hub and observability.

## Bootstrapping a cluster

1. Machines: A/D with the site's provisioning, using `infra/modules/rke2-node`'s user data; B/C with
   `tofu apply` in `infra/scenarios/b-cloud` or `c-hybrid-cloud` (`HCLOUD_TOKEN` and `TF_VAR_join_token` in the
   environment; never in files).
2. `deploy/bootstrap/install.sh` (Cilium, Argo CD, project). For C, install Cilium with the site's mesh values and
   the shared CA.
3. Either apply the overlay's root, `kubectl apply -k deploy/overlays/<scenario>`, or register the cluster in
   Rancher Fleet with label `difme/region`. Fleet (`deploy/fleet/bundle`) puts one root Application per cluster, and
   Argo CD syncs the overlay from git:
   - region-a: scenario A (primary);
   - region-b: scenario B (replica);
   - region-c: scenario B (disaster recovery).

## Not verified here

The overlays build in CI and the OpenTofu roots validate (with a module test of the rendered cloud-init), but no
real on-premises site, Hetzner project or ClusterMesh pair has been brought up from them. The first real bring-up
must check:
- BGP peering;
- the ClusterMesh connection and global service endpoints;
- the WireGuard routes.

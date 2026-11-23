# Scenario B (ADR-028): one RKE2 cluster on Hetzner Cloud VMs. Three servers behind a load balancer for the API and
# RKE2's join port, agents for workloads, a private network, a firewall that opens only the load balancer ports. After
# `tofu apply`: install Cilium + Argo CD (deploy/bootstrap/install.sh), then sync deploy/overlays/scenario-b-cloud
# (or register the cluster in Fleet with difme/region=region-b). Credentials only through variables / the
# HCLOUD_TOKEN environment variable, never in files.
terraform {
  required_version = ">= 1.9.0"
  required_providers {
    hcloud = { source = "hetznercloud/hcloud", version = "1.68.0" } # MPL-2.0
  }
}

variable "location" {
  type    = string
  default = "fsn1"
}
variable "server_type" {
  type    = string
  default = "cpx31"
}
variable "agent_type" {
  type    = string
  default = "cpx41"
}
variable "agents" {
  type    = number
  default = 3
}
variable "rke2_version" {
  type    = string
  default = "v1.33.5+rke2r1"
}
variable "api_host" {
  description = "DNS name pointing at the API load balancer"
  type        = string
  default     = "api.difme.internal"
}
variable "join_token" {
  type      = string
  sensitive = true
}
variable "ssh_keys" {
  description = "names of SSH keys already in the Hetzner project"
  type        = list(string)
  default     = []
}
variable "region_label" {
  type    = string
  default = "region-b"
}

resource "hcloud_network" "difme" {
  name     = "difme"
  ip_range = "10.10.0.0/16"
}

resource "hcloud_network_subnet" "nodes" {
  network_id   = hcloud_network.difme.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.10.1.0/24"
}

resource "hcloud_firewall" "nodes" {
  name = "difme-nodes"
  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["10.10.0.0/16"]
  }
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "any"
    source_ips = ["10.10.0.0/16"]
  }
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "any"
    source_ips = ["10.10.0.0/16"]
  }
}

module "server" {
  source       = "../../modules/rke2-node"
  count        = 3
  role         = "server"
  first_server = count.index == 0
  rke2_version = var.rke2_version
  api_host     = var.api_host
  join_token   = var.join_token
  node_labels  = { "difme/region" = var.region_label }
}

module "agent" {
  source       = "../../modules/rke2-node"
  role         = "agent"
  rke2_version = var.rke2_version
  api_host     = var.api_host
  join_token   = var.join_token
  node_labels  = { "difme/region" = var.region_label }
}

resource "hcloud_server" "server" {
  count        = 3
  name         = "difme-server-${count.index}"
  server_type  = var.server_type
  image        = "ubuntu-24.04"
  location     = var.location
  ssh_keys     = var.ssh_keys
  firewall_ids = [hcloud_firewall.nodes.id]
  user_data    = module.server[count.index].user_data
  labels       = { difme-role = "server" }
  network {
    network_id = hcloud_network.difme.id
  }
  depends_on = [hcloud_network_subnet.nodes]
}

resource "hcloud_server" "agent" {
  count        = var.agents
  name         = "difme-agent-${count.index}"
  server_type  = var.agent_type
  image        = "ubuntu-24.04"
  location     = var.location
  ssh_keys     = var.ssh_keys
  firewall_ids = [hcloud_firewall.nodes.id]
  user_data    = module.agent.user_data
  labels       = { difme-role = "agent" }
  network {
    network_id = hcloud_network.difme.id
  }
  depends_on = [hcloud_network_subnet.nodes]
}

# API (6443) and RKE2 join (9345) for the servers; ingress (80/443) for the agents (Envoy Gateway).
resource "hcloud_load_balancer" "api" {
  name               = "difme-api"
  load_balancer_type = "lb11"
  location           = var.location
}

resource "hcloud_load_balancer_network" "api" {
  load_balancer_id = hcloud_load_balancer.api.id
  network_id       = hcloud_network.difme.id
}

resource "hcloud_load_balancer_target" "servers" {
  type             = "label_selector"
  load_balancer_id = hcloud_load_balancer.api.id
  label_selector   = "difme-role=server"
  use_private_ip   = true
  depends_on       = [hcloud_load_balancer_network.api]
}

resource "hcloud_load_balancer_service" "api" {
  for_each         = toset(["6443", "9345"])
  load_balancer_id = hcloud_load_balancer.api.id
  protocol         = "tcp"
  listen_port      = tonumber(each.value)
  destination_port = tonumber(each.value)
}

output "api_load_balancer_ip" {
  description = "point api_host (DNS) here"
  value       = hcloud_load_balancer.api.ipv4
}

output "server_private_ips" {
  value = [for s in hcloud_server.server : one(s.network[*].ip)]
}

output "network_id" {
  description = "private network (scenario C attaches its WireGuard gateway here)"
  value       = hcloud_network.difme.id
}

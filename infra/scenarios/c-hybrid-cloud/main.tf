# Scenario C, cloud site (ADR-028): scenario B's cluster for the stateless edge tier, plus a WireGuard gateway to the
# on-premises site. Cilium ClusterMesh needs the two clusters' nodes and pods to reach each other: the private
# network routes the on-premises ranges through the gateway, and the on-premises router routes 10.10.0.0/16 and the
# cloud pod range (10.48.0.0/12, deploy/overlays/values/cilium-mesh-cloud.yaml) back through its WireGuard peer.
# After apply: sync deploy/overlays/scenario-c-hybrid/cloud (Fleet: difme/region=region-c).
terraform {
  required_version = ">= 1.9.0"
  required_providers {
    hcloud = { source = "hetznercloud/hcloud", version = "1.68.0" } # MPL-2.0
  }
}

variable "join_token" {
  type      = string
  sensitive = true
}
variable "ssh_keys" {
  type    = list(string)
  default = []
}
variable "location" {
  type    = string
  default = "fsn1"
}
variable "onprem_public_ip" {
  description = "public address of the on-premises WireGuard peer"
  type        = string
}
variable "onprem_wg_public_key" {
  description = "WireGuard public key of the on-premises peer (public, not secret)"
  type        = string
}
variable "onprem_ranges" {
  description = "on-premises node and pod ranges reached through the tunnel (pods: cilium-mesh-onprem.yaml)"
  type        = list(string)
  default     = ["10.20.0.0/16", "10.32.0.0/12"]
}

module "cluster" {
  source       = "../b-cloud"
  join_token   = var.join_token
  ssh_keys     = var.ssh_keys
  location     = var.location
  agents       = 2
  region_label = "region-c"
}

# The gateway generates its own WireGuard key at first boot (it never leaves the VM); read its public key from
# /etc/wireguard/public.key and give it to the on-premises peer.
resource "hcloud_server" "wg" {
  name        = "difme-wg-gateway"
  server_type = "cx22"
  image       = "ubuntu-24.04"
  location    = var.location
  ssh_keys    = var.ssh_keys
  user_data   = <<-EOT
    #cloud-config
    packages: [wireguard]
    write_files:
      - path: /etc/sysctl.d/99-forward.conf
        content: "net.ipv4.ip_forward=1\n"
    runcmd:
      - sysctl --system
      - umask 077 && wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
      - printf '[Interface]\nAddress = 10.99.0.1/30\nListenPort = 51820\nPostUp = wg set %%i private-key /etc/wireguard/private.key\n[Peer]\nPublicKey = ${var.onprem_wg_public_key}\nEndpoint = ${var.onprem_public_ip}:51820\nAllowedIPs = ${join(", ", var.onprem_ranges)}, 10.99.0.2/32\nPersistentKeepalive = 25\n' > /etc/wireguard/wg0.conf
      - systemctl enable --now wg-quick@wg0
  EOT
  network {
    network_id = module.cluster.network_id
    ip         = "10.10.1.250"
  }
}

resource "hcloud_firewall" "wg" {
  name = "difme-wg"
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51820"
    source_ips = ["${var.onprem_public_ip}/32"]
  }
  apply_to {
    server = hcloud_server.wg.id
  }
}

resource "hcloud_network_route" "onprem" {
  for_each    = toset(var.onprem_ranges)
  network_id  = module.cluster.network_id
  destination = each.value
  gateway     = "10.10.1.250"
}

output "api_load_balancer_ip" {
  value = module.cluster.api_load_balancer_ip
}

output "wg_gateway_public_ip" {
  value = hcloud_server.wg.ipv4_address
}

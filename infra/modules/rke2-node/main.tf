# Provider-neutral RKE2 node bootstrap (ADR-028): renders the cloud-init user data that installs RKE2 with DIFME's CIS
# configuration (deploy/fleet/rke2-config.yaml) on any VM or bare-metal host that runs cloud-init. Cloud roots pass it
# as their servers' user data; on-premises (scenario A) the same output feeds the site's provisioning (PXE/MAAS/ISO).

variable "role" {
  description = "server (control plane + etcd) or agent"
  type        = string
  validation {
    condition     = contains(["server", "agent"], var.role)
    error_message = "role must be server or agent."
  }
}

variable "rke2_version" {
  description = "RKE2 release, e.g. v1.33.5+rke2r1"
  type        = string
}

variable "api_host" {
  description = "DNS name of the Kubernetes API load balancer (api.difme.internal in the overlays' Cilium values)"
  type        = string
}

variable "join_token" {
  description = "RKE2 cluster join token (from the operator's secret store; never committed)"
  type        = string
  sensitive   = true
}

variable "first_server" {
  description = "true on the server that initialises the cluster"
  type        = bool
  default     = false
}

variable "node_labels" {
  description = "Kubernetes node labels, e.g. { \"difme/region\" = \"region-b\" }"
  type        = map(string)
  default     = {}
}

locals {
  # Servers get the CIS hardening profile and its settings; agents only join (the profile applies cluster-wide).
  # Values are written as JSON, which is valid YAML.
  config = join("", [
    var.role == "server" ? "${trimspace(file("${path.module}/../../../deploy/fleet/rke2-config.yaml"))}\ntls-san: ${jsonencode([var.api_host])}\n" : "",
    "token: ${jsonencode(var.join_token)}\n",
    var.first_server ? "" : "server: ${jsonencode("https://${var.api_host}:9345")}\n",
    "node-label: ${jsonencode([for k, v in var.node_labels : "${k}=${v}"])}\n",
  ])
}

output "user_data" {
  description = "cloud-init user data for this node"
  sensitive   = true
  value       = <<-EOT
    #cloud-config
    write_files:
      - path: /etc/rancher/rke2/config.yaml
        permissions: "0600"
        content: ${jsonencode(local.config)}
    runcmd:
      - curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION=${var.rke2_version} INSTALL_RKE2_TYPE=${var.role} sh -
      - systemctl enable --now rke2-${var.role}.service
  EOT
}

###############################################################################
# IoC Sentinel - Vultr infrastructure
#
#   Internet ──► Vultr Firewall (22 from admin_cidrs, 80/443 public)
#                  │
#                  ▼
#   ┌──────────── control-plane VM (public IP + VPC NIC 10.40.0.x) ──────────┐
#   │  FastAPI orchestrator · secrets · docker                               │
#   │    └─ ioc-jail bridge 172.30.0.0/24 ──► Internet :80/:443 only         │
#   │         ✕ 169.254.169.254   ✕ 10.0.0.0/8 (this VPC)   ✕ the VM itself  │
#   └────────────────────────────────────────────────────────────────────────┘
#                  │ VPC (private, no public exposure)
#                  ▼
#   future: sandbox worker nodes / managed DB / object storage endpoints
#
# The VPC carries control-plane <-> future-worker traffic only. The sandbox
# jail rejects every RFC1918 destination, so a compromised page can never
# pivot into the VPC.
###############################################################################

locals {
  name        = var.project
  ssh_pubkey  = trimspace(file(pathexpand(var.ssh_public_key_path)))
  repo_dir    = "/opt/ioc-sentinel"
  admin_rules = { for c in var.admin_cidrs : c => { ip = split("/", c)[0], size = tonumber(split("/", c)[1]) } }
}

data "vultr_os" "ubuntu" {
  filter {
    name   = "name"
    values = [var.os_name]
  }
}

# --------------------------------------------------------------------------- #
# Access
# --------------------------------------------------------------------------- #
resource "vultr_ssh_key" "admin" {
  name    = "${local.name}-admin"
  ssh_key = local.ssh_pubkey
}

# --------------------------------------------------------------------------- #
# Network: VPC + edge firewall
# --------------------------------------------------------------------------- #
resource "vultr_vpc" "main" {
  description    = "${local.name}-vpc"
  region         = var.region
  v4_subnet      = var.vpc_subnet
  v4_subnet_mask = var.vpc_subnet_mask
}

resource "vultr_firewall_group" "control_plane" {
  description = "${local.name}-control-plane"
}

resource "vultr_firewall_rule" "ssh_admin" {
  for_each          = local.admin_rules
  firewall_group_id = vultr_firewall_group.control_plane.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = each.value.ip
  subnet_size       = each.value.size
  port              = "22"
  notes             = "ssh admin ${each.key}"
}

resource "vultr_firewall_rule" "api_admin" {
  for_each          = var.expose_api_port ? local.admin_rules : {}
  firewall_group_id = vultr_firewall_group.control_plane.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = each.value.ip
  subnet_size       = each.value.size
  port              = "8000"
  notes             = "fastapi dev ${each.key}"
}

resource "vultr_firewall_rule" "web" {
  for_each          = toset(["80", "443"])
  firewall_group_id = vultr_firewall_group.control_plane.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = each.value
  notes             = "public web ${each.value}"
}

resource "vultr_firewall_rule" "icmp" {
  firewall_group_id = vultr_firewall_group.control_plane.id
  protocol          = "icmp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  notes             = "ping"
}

# --------------------------------------------------------------------------- #
# Optional stable public IP
# --------------------------------------------------------------------------- #
resource "vultr_reserved_ip" "control_plane" {
  count   = var.use_reserved_ip ? 1 : 0
  label   = "${local.name}-ip"
  region  = var.region
  ip_type = "v4"
}

# --------------------------------------------------------------------------- #
# Control-plane VM
# --------------------------------------------------------------------------- #
resource "vultr_instance" "control_plane" {
  label             = "${local.name}-control-plane"
  hostname          = "${local.name}-cp"
  region            = var.region
  plan              = var.plan
  os_id             = data.vultr_os.ubuntu.id
  ssh_key_ids       = [vultr_ssh_key.admin.id]
  vpc_ids           = [vultr_vpc.main.id]
  firewall_group_id = vultr_firewall_group.control_plane.id
  reserved_ip_id    = var.reserved_ip_id != "" ? var.reserved_ip_id : (var.use_reserved_ip ? vultr_reserved_ip.control_plane[0].id : null)
  enable_ipv6       = false # jail is IPv4-only; no v6 path to worry about
  backups           = "disabled"
  activation_email  = false
  ddos_protection   = false
  tags              = var.tags

  # NOTE: no secrets in user_data. Vultr serves it from the metadata service,
  # exactly the endpoint the sandbox jail blocks. Secrets go in via `make tf-env`.
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_user    = var.admin_user
    ssh_pubkey    = local.ssh_pubkey
    repo_url      = var.repo_url
    repo_ref      = var.repo_ref
    repo_dir      = local.repo_dir
    enable_gvisor = var.enable_gvisor
    vpc_cidr      = "${var.vpc_subnet}/${var.vpc_subnet_mask}"
  })

  lifecycle {
    # cloud-init only runs on first boot; editing the template must not trigger
    # a surprise in-place update that does nothing.
    ignore_changes = [user_data]
  }
}

# --------------------------------------------------------------------------- #
# Serverless Inference (the agent's LLM; GPUs are disabled for this event)
# --------------------------------------------------------------------------- #
resource "vultr_inference" "agent" {
  count = var.create_inference ? 1 : 0
  label = "${local.name}-agent"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "ioc-sentinel"
}

variable "region" {
  description = "Vultr region ID. mia (Miami) / atl (Atlanta) are closest to Panama."
  type        = string
  default     = "mia"
}

variable "plan" {
  description = "Cloud Compute plan for the control-plane VM (Chromium + Docker builds need >= 4 GB)."
  type        = string
  default     = "vc2-2c-4gb"
}

variable "os_name" {
  description = "Exact Vultr OS name."
  type        = string
  default     = "Ubuntu 24.04 LTS x64"
}

variable "ssh_public_key_path" {
  description = "Path to the public key that will be authorized for the admin user."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "admin_user" {
  description = "Non-root sudo user created by cloud-init (root SSH login is disabled)."
  type        = string
  default     = "juanjo"
}

variable "admin_cidrs" {
  description = "CIDRs allowed to SSH (and reach :8000 when expose_api_port). Use your public IP /32."
  type        = list(string)

  validation {
    condition     = length(var.admin_cidrs) > 0 && alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0))])
    error_message = "admin_cidrs must be a non-empty list of valid IPv4 CIDRs, e.g. [\"190.140.10.20/32\"]."
  }
}

variable "expose_api_port" {
  description = "Open tcp/8000 (FastAPI, no TLS) to admin_cidrs during development."
  type        = bool
  default     = false
}

variable "vpc_subnet" {
  description = "VPC IPv4 network. Must not overlap the sandbox jail (172.30.0.0/24) or Docker defaults (172.17.0.0/16)."
  type        = string
  default     = "10.40.0.0"
}

variable "vpc_subnet_mask" {
  type    = number
  default = 24
}

variable "repo_url" {
  description = "HTTPS git URL cloud-init clones into /opt/ioc-sentinel. Leave empty to push code with `make tf-sync` instead (private repos)."
  type        = string
  default     = ""
}

variable "repo_ref" {
  description = "Branch or tag to check out."
  type        = string
  default     = "main"
}

variable "enable_gvisor" {
  description = "Install gVisor (runsc) and use it as the sandbox runtime. Default false: runsc breaks DNS on user-defined Docker networks (README, lesson 2)."
  type        = bool
  default     = false
}

variable "use_reserved_ip" {
  description = "Attach a reserved IPv4 so the public IP survives instance rebuilds (handy for the demo DNS)."
  type        = bool
  default     = false
}

variable "create_inference" {
  description = "Create the Vultr Serverless Inference subscription with Terraform (its API key becomes a sensitive output)."
  type        = bool
  default     = true
}

variable "tags" {
  type    = list(string)
  default = ["ioc-sentinel", "agent-rush"]
}

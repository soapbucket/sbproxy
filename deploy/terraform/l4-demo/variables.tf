variable "project" {
  type        = string
  description = "GCP project id."
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "name" {
  type        = string
  default     = "sbproxy-l4-demo"
  description = "Name prefix for the instance and its network resources."
}

variable "machine_type" {
  type    = string
  default = "g2-standard-4" # 1 NVIDIA L4, 4 vCPU, 16GB
}

variable "image" {
  type        = string
  default     = "projects/deeplearning-platform-release/global/images/family/common-cu124-debian-11"
  description = "Boot image. The Deep Learning VM CUDA family ships the NVIDIA driver + CUDA toolkit."
}

variable "disk_gb" {
  type    = number
  default = 150
}

variable "ssh_user" {
  type    = string
  default = "sbproxy"
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key contents for var.ssh_user (e.g. file(\"~/.ssh/id_ed25519.pub\"))."
}

variable "ssh_source_cidr" {
  type        = string
  description = "CIDR allowed to SSH (lock to your IP, e.g. 203.0.113.4/32)."
}

variable "acme_domain" {
  type        = string
  description = "Public hostname for the Let's Encrypt cert (must resolve to the instance's external IP)."
}

variable "acme_email" {
  type        = string
  description = "Contact email for the ACME account."
}

variable "bearer_token" {
  type        = string
  sensitive   = true
  description = "Bearer token clients must present. Generate a long random value."
}

variable "serve_models" {
  type = list(object({
    model      = string           # catalog id (e.g. "qwen3-14b") OR "hf:Org/Repo:QUANT"
    name       = optional(string) # plane-visible id; REQUIRED for an hf: ref
    keep_alive = optional(string, "30m")
  }))
  # Two entries by default, one of each serve type: a built-in catalog id
  # (the fit planner picks the quant the L4 can run) and a raw hf:
  # reference (a non-catalog model, needs an explicit name). Add or swap
  # entries to test other models; both fit a 24GB L4 at these quants.
  default = [
    {
      model = "qwen3-14b"
    },
    {
      model = "hf:THUDM/codegeex4-all-9b-GGUF:Q4_K_M"
      name  = "codegeex4-all-9b"
    },
  ]
  description = "Models the sbproxy model host serves locally. Each is a catalog id or an hf:Org/Repo:QUANT reference."
}

variable "cache_budget_gib" {
  type        = number
  default     = 20
  description = "VRAM budget for the resident model set (L4 has 24GB)."
}

variable "repo_url" {
  type    = string
  default = "https://github.com/soapbucket/sbproxy.git"
}

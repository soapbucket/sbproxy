# Stand up a single-L4 GPU box on GCP that serves a local model behind
# sbproxy, reachable over a public IP with TLS and a bearer token. This
# is the infrastructure for the "run your own model, govern it" demo;
# the box itself is configured by startup.sh.
#
# Cost: a g2-standard-4 (1 NVIDIA L4) is ~$0.71/hr on-demand
# (~$516/mo), plus the boot disk and a static IP. Run `terraform
# destroy` when you are done.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

locals {
  # A domain means public HTTPS via ACME (start after DNS); no domain
  # means the plain-HTTP one-command demo keyed to the public IP, started
  # at boot.
  tls_enabled = var.acme_domain != ""
  # In plain-HTTP mode the origin is keyed to the public IP, which is not
  # known at plan time (templatefile forbids unknown values), so we render
  # a sentinel and the startup script substitutes the real IP at boot.
  public_host = local.tls_enabled ? var.acme_domain : "SBPROXY_PUBLIC_HOST"
  auto_start  = !local.tls_enabled

  # release mode: curl-install the binary + let sbproxy acquire the
  # engine. source mode: build sbproxy + CUDA llama.cpp from source.
  startup_script = var.install_mode == "release" ? "startup-release.sh" : "startup.sh"

  # Render the sbproxy config from the model list. default_model is the
  # first served model's plane-visible name.
  sbproxy_config = templatefile("${path.module}/sbproxy.yml.tftpl", {
    tls_enabled      = local.tls_enabled
    public_host      = local.public_host
    acme_email       = var.acme_email
    engine_accel     = var.engine_accel
    admin_password   = var.bearer_token
    bearer_token     = var.bearer_token
    default_model    = coalesce(var.serve_models[0].name, var.serve_models[0].model)
    serve_models     = var.serve_models
    cache_budget_gib = var.cache_budget_gib
  })
}

# A reserved external IP so the demo hostname (var.acme_domain) keeps
# resolving to the same address across instance restarts.
resource "google_compute_address" "demo" {
  name = "${var.name}-ip"
}

# Open the ports the demo needs: SSH (locked to your CIDR), HTTP-01 for
# the ACME challenge, and HTTPS for the admin + data planes. The bearer
# token is enforced by sbproxy at the application layer, not the firewall.
resource "google_compute_firewall" "demo" {
  name    = "${var.name}-fw"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8791"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [var.name]
}

resource "google_compute_firewall" "ssh" {
  name    = "${var.name}-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = [var.ssh_source_cidr]
  target_tags   = [var.name]
}

resource "google_compute_instance" "demo" {
  name         = var.name
  machine_type = var.machine_type # g2-standard-4 includes 1 NVIDIA L4
  tags         = [var.name]

  # GPUs cannot live-migrate, so the host-maintenance policy must
  # terminate-and-restart rather than migrate.
  scheduling {
    on_host_maintenance = "TERMINATE"
    automatic_restart   = true
  }

  boot_disk {
    initialize_params {
      # Deep Learning VM image: NVIDIA driver + CUDA toolkit preinstalled,
      # so llama.cpp can build against CUDA without a driver dance.
      image = var.image
      size  = var.disk_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.demo.address
    }
  }

  metadata = {
    # The startup script (static; reads its inputs from metadata to avoid
    # Terraform interpolating bash) installs sbproxy, writes the rendered
    # config from `sbproxy-config`, and installs a systemd unit. In
    # release mode it curl-installs the binary and lets sbproxy acquire
    # the engine, then auto-starts (plain HTTP) or waits for DNS (TLS).
    startup-script = file("${path.module}/${local.startup_script}")
    sbproxy-config = local.sbproxy_config
    install-url    = var.install_url
    auto-start     = tostring(local.auto_start)
    repo-url       = var.repo_url # source mode only
    ssh-keys       = "${var.ssh_user}:${var.ssh_public_key}"
    # DLVM images install the NVIDIA driver on first boot when this is set.
    install-nvidia-driver = "True"
  }

  labels = {
    purpose = "sbproxy-l4-demo"
  }
}

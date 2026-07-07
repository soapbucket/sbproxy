output "external_ip" {
  value       = google_compute_address.demo.address
  description = "The instance's external IP."
}

output "endpoint" {
  value       = local.tls_enabled ? "https://${var.acme_domain}" : "http://${google_compute_address.demo.address}"
  description = "The data-plane endpoint. Send requests with Authorization: Bearer <token>."
}

output "ssh" {
  value       = "ssh ${var.ssh_user}@${google_compute_address.demo.address}"
  description = "SSH into the instance."
}

output "admin_url" {
  value       = local.tls_enabled ? "https://${var.acme_domain}/admin/ui" : "http://127.0.0.1:9090/admin/ui (via SSH tunnel -L 9090:localhost:9090)"
  description = "Admin UI (loopback; tunnel over SSH in plain-HTTP mode)."
}

locals {
  next_tls = <<-EOT
    TLS mode (${var.install_mode}):
    1. Point ${var.acme_domain} A record -> ${google_compute_address.demo.address}
    2. Start after DNS: gcloud compute ssh ${var.name} -- 'sudo systemctl start sbproxy'
       (watch: sudo journalctl -u sbproxy -f). The first request acquires the
       engine, pulls the weights, and serves.
    3. Data plane: https://${var.acme_domain} with `Authorization: Bearer <token>`.
    4. terraform destroy when done.
  EOT

  next_plain = <<-EOT
    One-command mode (${var.install_mode}): sbproxy is already starting.
    1. First request (acquires engine + pulls weights, so allow a few minutes):
         curl http://${google_compute_address.demo.address}/v1/chat/completions \
           -H "Authorization: Bearer <token>" -H "content-type: application/json" \
           -d '{"model":"${coalesce(var.serve_models[0].name, var.serve_models[0].model)}","messages":[{"role":"user","content":"hello"}]}'
       (watch: gcloud compute ssh ${var.name} -- 'sudo journalctl -u sbproxy -f')
    2. terraform destroy when done.
  EOT
}

output "next_steps" {
  value       = local.tls_enabled ? local.next_tls : local.next_plain
  description = "What to do after apply."
}

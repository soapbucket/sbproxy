output "external_ip" {
  value       = google_compute_address.demo.address
  description = "Point var.acme_domain's A record at this address, then TLS issues on first request."
}

output "ssh" {
  value       = "ssh ${var.ssh_user}@${google_compute_address.demo.address}"
  description = "SSH into the instance."
}

output "admin_url" {
  value       = "https://${var.acme_domain}/admin/ui"
  description = "Admin UI once DNS resolves and the cert is issued."
}

output "next_steps" {
  value = <<-EOT
    1. Point ${var.acme_domain} A record -> ${google_compute_address.demo.address}
    2. Wait for the startup script to build sbproxy + fetch the model
       (watch: gcloud compute ssh ${var.name} -- 'sudo journalctl -u sbproxy -f').
    3. Admin UI: https://${var.acme_domain}/admin/ui
    4. Data plane: send requests with `Authorization: Bearer <token>`.
    5. terraform destroy when done.
  EOT
}

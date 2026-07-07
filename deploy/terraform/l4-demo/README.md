# L4 GPU demo: run your own models behind sbproxy

Terraform to stand up a single-GPU box on GCP that serves local models
through sbproxy. It is the "call any model, serve your own, govern both"
demo you can run end to end and then tear down.

Two modes, chosen by `install_mode`:

- **`release` (default): one command, no build.** Installs the released
  sbproxy binary via the curl installer and lets sbproxy **acquire the
  inference engine itself** (WOR-1801), so there is no source build and no
  hand-built llama.cpp. With no `acme_domain` it serves plain HTTP on the
  public IP and **auto-starts at boot**, so `terraform apply` reaches a
  served model on the first request with no manual engine step. Requires a
  release with `gpu-nvidia` + `model-weights` (v1.5.0+).
- **`source`: build from source.** Builds sbproxy + a native-CUDA
  llama.cpp on the box (slower first boot, native-CUDA engine). This is
  the original demo path.

Set an `acme_domain` in either mode for public HTTPS via Let's Encrypt
(started after DNS resolves, see below).

## What it creates

- A `g2-standard-4` (1 NVIDIA L4, 24 GB) on a Deep Learning VM image
  (NVIDIA driver preinstalled).
- A reserved external IP, and firewall rules for 80/443 (public) and 22
  (locked to your CIDR).
- A startup script that installs (or builds) sbproxy and serves the
  models you list, bearer-token protected.

Cost: the L4 box is about $0.71/hr on-demand (~$516/mo), plus a small
disk and the static IP. Run `terraform destroy` when you are done.

## One command (release mode)

```hcl
# terraform.tfvars
project         = "your-project"
bearer_token    = "PASTE_A_LONG_RANDOM_VALUE"   # openssl rand -hex 32
ssh_public_key  = "ssh-ed25519 AAAA... you@host"
ssh_source_cidr = "203.0.113.4/32"              # your IP
# no acme_domain -> plain HTTP on the public IP, auto-starts at boot
```

```bash
terraform init && terraform apply
# The box installs sbproxy and starts it. The first request acquires the
# engine, pulls the weights, and serves (allow a few minutes):
curl http://<external_ip>/v1/chat/completions \
  -H "Authorization: Bearer $BEARER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"codegeex4-all-9b","messages":[{"role":"user","content":"hello"}]}'
```

No DNS, no source build, no manual engine install. For public HTTPS, set
`acme_domain` and follow the TLS section below.

### Cloud-agnostic variant

`cloud-init.yaml` is the same bootstrap as plain user-data for any GPU box
whose image carries the NVIDIA driver (a GCP DLVM, an AWS DLAMI, ...):
edit the bearer token and pass it as the instance user-data. It
curl-installs sbproxy, lets it acquire the engine, and serves.

## Serving models: both reference types

`serve_models` takes a list, so you can serve and test several models at
once. Each entry is one of two types:

- A built-in **catalog id** (`qwen3-14b`): the fit planner picks the
  quant the GPU can run.
- A raw **`hf:Org/Repo:QUANT`** reference for anything not in the
  catalog (needs an explicit `name`).

The default serves one of each, so you see both:

```hcl
serve_models = [
  { model = "qwen3-14b" },                                    # catalog
  { model = "hf:THUDM/codegeex4-all-9b-GGUF:Q4_K_M",          # hf: ref
    name  = "codegeex4-all-9b" },
]
```

Swap or add entries to test your own; both above fit a 24 GB L4.

## Public HTTPS (Let's Encrypt)

For a public TLS endpoint, add a DNS name you control. Create
`terraform.tfvars`:

```hcl
project         = "your-project"
acme_domain     = "demo.sbproxy.dev"
acme_email      = "you@example.com"             # optional; LE expiry notices go here
bearer_token    = "PASTE_A_LONG_RANDOM_VALUE"   # e.g. openssl rand -hex 32
ssh_public_key  = "ssh-ed25519 AAAA... you@host"
ssh_source_cidr = "203.0.113.4/32"              # your IP
# install_mode  = "source"  # optional: build a native-CUDA engine instead
```

Then:

```bash
terraform init
terraform apply

# 1. Point the A record at the printed external_ip:
#    demo.sbproxy.dev -> <external_ip>
# 2. Watch the boot (release mode: seconds to install; source mode:
#    about 20-30 min to build):
gcloud compute ssh sbproxy-l4-demo -- 'sudo journalctl -u sbproxy -f'
# 3. Once DNS resolves, start sbproxy so ACME can issue (TLS mode does not
#    auto-start, since issuance needs the domain live first):
gcloud compute ssh sbproxy-l4-demo -- 'sudo systemctl start sbproxy'
```

### DNS on Cloudflare

sbproxy runs Let's Encrypt itself (ACME `tls-alpn-01` / `http-01`), so the
challenge and TLS must reach the box directly. Add the record as **DNS
only (grey cloud), not proxied**:

- Type `A`, name `demo`, content `<external_ip>`, Proxy status **DNS only**.

If you leave it **proxied (orange cloud)**, Cloudflare terminates TLS at
its edge and intercepts 80/443, so sbproxy's ACME cannot validate. To use
the orange cloud instead, turn sbproxy's `acme` off, run plain HTTP on the
origin, and rely on Cloudflare's edge TLS plus an Origin certificate.

The provider's Application Default Credentials must be current
(`gcloud auth application-default login`) or `terraform apply` fails with
a reauth error.

## Use it

Send an OpenAI-shaped request with the bearer token (served by the local
model):

```bash
curl https://demo.sbproxy.dev/v1/chat/completions \
  -H "Authorization: Bearer $BEARER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"codegeex4-all-9b","messages":[{"role":"user","content":"Write a Rust fn to reverse a string."}]}'
```

The admin server stays on loopback; reach the dashboard over an SSH
tunnel:

```bash
gcloud compute ssh sbproxy-l4-demo -- -L 9090:localhost:9090
# then open http://localhost:9090/admin/ui  (Model host + Metrics show
# resident models, VRAM, and tokens/sec)
```

## Tear down

```bash
terraform destroy
```

See [`self-hosting.md`](../../../docs/self-hosting.md) and
[`admin.md`](../../../docs/admin.md) for the model host and admin surface.

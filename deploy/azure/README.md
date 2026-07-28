# Azure GPU setup: run your own models behind sbproxy

Instructions for standing up a single-GPU Azure VM that serves local
models through sbproxy, without Terraform: one `az vm create`, and the
same cloud-agnostic bootstrap the GCP demo uses. This is the Azure twin
of [`deploy/terraform/l4-demo`](../terraform/l4-demo/README.md); that
directory has the Terraform module (reserved IP, ACME TLS, firewall
rules). This page is deliberately not a Terraform module: it is the
az-cli equivalent of the L4 demo's ["cloud-agnostic
variant"](../terraform/l4-demo/README.md#cloud-agnostic-variant),
scoped to getting a box up with a couple of commands.

## What you need

- A GPU VM size with enough VRAM for the model you want to serve. The
  NCads_A10_v4-series (e.g. `Standard_NC8ads_A10_v4`, a partitioned
  NVIDIA A10 with 24 GB VRAM at the largest partition) is the closest
  match to the GCP demo's single-L4 box. The older NCasT4_v3-series
  (`Standard_NC4as_T4_v3`, one NVIDIA T4, 16 GB VRAM) is a cheaper
  entry point if 16 GB fits your quant. Both need GPU quota approved in
  your subscription/region before `az vm create` succeeds; request it
  from the Azure portal's Quotas blade if you have not used GPU VMs
  here before.
- An Ubuntu 22.04 LTS image, plus the NVIDIA driver: unlike the GCP
  Deep Learning VM image, most Ubuntu marketplace images on Azure do
  not ship the driver preinstalled, so install it as a VM extension
  after create (below). If you would rather start from an image with
  the driver already on it, the Azure Data Science Virtual Machine
  image is the marketplace alternative.
- A network security group open on 22 (locked to your IP), 80, and 443.
- An SSH key pair.

## One command

Edit a copy of [`../terraform/l4-demo/cloud-init.yaml`](../terraform/l4-demo/cloud-init.yaml)
first: it is the custom-data this box boots with, and it embeds the
sbproxy config inline. Set a real bearer token and admin password
(`CHANGE-ME-BEARER-TOKEN`, `CHANGE-ME-ADMIN`), and swap the served
model if you don't want the default CodeGeeX4 GGUF. See that file's
header comment for the full "edit before use" list.

The config's origin is keyed to `model.local` (not this box's public
IP), so requests need a matching `Host:` header. See "Use it" below.

```bash
az vm create \
  --resource-group your-resource-group \
  --name sbproxy-gpu-demo \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
  --size Standard_NC8ads_A10_v4 \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_ed25519.pub \
  --os-disk-size-gb 150 \
  --custom-data cloud-init.yaml \
  --public-ip-sku Standard

az vm open-port --resource-group your-resource-group --name sbproxy-gpu-demo --port 80 --priority 900
az vm open-port --resource-group your-resource-group --name sbproxy-gpu-demo --port 443 --priority 901
```

Install the NVIDIA driver extension (skip this if you started from the
Data Science VM image, which already has it):

```bash
az vm extension set \
  --resource-group your-resource-group \
  --vm-name sbproxy-gpu-demo \
  --name NvidiaGpuDriverLinux \
  --publisher Microsoft.HpcCompute
```

Watch the boot (bootstrap logs to `/var/log/sbproxy-bootstrap.log` on
the box, same as every other cloud this script runs on):

```bash
PUBLIC_IP="$(az vm show -d --resource-group your-resource-group --name sbproxy-gpu-demo --query publicIps -o tsv)"
ssh azureuser@"$PUBLIC_IP" 'sudo tail -f /var/log/sbproxy-bootstrap.log'
```

## What actually runs the box

`cloud-init.yaml` embeds
[`bootstrap-generic.sh`](../terraform/l4-demo/bootstrap-generic.sh)
verbatim (the same cloud-agnostic script the GCP path wraps) rather
than fetching it over the network at boot, and its `runcmd` runs it
with `AUTO_START=true`. That script installs the released sbproxy binary,
runs `sbproxy doctor --format json` to report the host's GPU, driver,
shared-memory, and cache-budget state before serving anything, installs
the systemd unit, and starts it. See that script's header comment for
every input it reads; this box does not need `SBPROXY_PUBLIC_HOST`
since the config keys on a fixed `Host:` header, not an IP.

## Use it

```bash
curl http://$PUBLIC_IP/v1/chat/completions \
  -H 'Host: model.local' \
  -H "Authorization: Bearer $BEARER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"codegeex4-all-9b","messages":[{"role":"user","content":"hello"}]}'
```

Allow a few minutes on the first request: it acquires the inference
engine and pulls the weights before it can answer.

The admin server stays on loopback; reach it over an SSH tunnel:

```bash
ssh -L 9090:localhost:9090 azureuser@$PUBLIC_IP
# then open http://localhost:9090/admin/ui
```

## Public HTTPS

`cloud-init.yaml` serves plain HTTP only. For TLS without hand-rolling
Terraform, either put the box behind Azure Application Gateway or Front
Door with TLS termination there, or edit the embedded config to add
sbproxy's own `acme:` block (see
[`sbproxy.yml.tftpl`](../terraform/l4-demo/sbproxy.yml.tftpl) for the
shape) and point a DNS record at the VM's public IP before the ACME
challenge can complete. The Terraform module in
[`deploy/terraform/l4-demo`](../terraform/l4-demo/README.md) does this
for you if you would rather not hand-edit YAML.

## Tear down

```bash
az vm deallocate --resource-group your-resource-group --name sbproxy-gpu-demo
az group delete --name your-resource-group --yes
```

Cost: check current pricing for the size and region you picked (GPU VM
pricing varies widely by region and availability); deallocate or delete
the resource group when you are done so the GPU stops billing.

See [`self-hosting.md`](../../docs/self-hosting.md) and
[`admin.md`](../../docs/admin.md) for the model host and admin surface,
and [`use-case-serve-on-l4.md`](../../docs/use-case-serve-on-l4.md) for
the full config walkthrough this box's `serve:` block comes from.

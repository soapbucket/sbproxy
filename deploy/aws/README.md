# AWS GPU setup: run your own models behind sbproxy

Instructions for standing up a single-GPU EC2 box that serves local
models through sbproxy, without Terraform: an AMI lookup, one
`aws ec2 run-instances`, and the same cloud-agnostic bootstrap the GCP
demo uses. This is the AWS twin of
[`deploy/terraform/l4-demo`](../terraform/l4-demo/README.md); that
directory has the Terraform module (reserved IP, ACME TLS, firewall
rules). This page is deliberately not a Terraform module: it is the
aws-cli equivalent of the L4 demo's ["cloud-agnostic
variant"](../terraform/l4-demo/README.md#cloud-agnostic-variant),
scoped to getting a box up with a couple of commands.

## What you need

- An instance type with one GPU and enough VRAM for the model you want
  to serve. `g6.xlarge` (1x NVIDIA L4, 24 GB VRAM, 4 vCPU) is the
  closest match to the GCP demo's `g2-standard-4`. `g5.xlarge` (1x
  NVIDIA A10G, 24 GB VRAM) is the same tier on the previous generation
  and is often cheaper or more available in a given region/AZ.
- A GPU-ready AMI: an NVIDIA driver already installed, so there is no
  driver dance on first boot. AWS publishes these as the "Deep Learning
  Base OSS Nvidia Driver GPU AMI" family. Resolve the current AMI id
  rather than hardcoding one (AWS rotates them):

  ```bash
  AMI_ID="$(aws ec2 describe-images \
    --owners amazon \
    --filters \
      "Name=name,Values=Deep Learning Base OSS Nvidia Driver GPU AMI*Ubuntu 22.04*" \
      "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)"
  echo "$AMI_ID"
  ```

  Adjust the `Name=name` filter if AWS has renamed the listing since
  this was written; `aws ec2 describe-images --owners amazon --filters
  "Name=name,Values=Deep Learning*"` lists what is currently published.
- A security group open on 22 (locked to your IP), 80, and 443.
- A key pair for SSH.

## One command

Edit a copy of [`../terraform/l4-demo/cloud-init.yaml`](../terraform/l4-demo/cloud-init.yaml)
first: it is the user-data this box boots with, and it embeds the
sbproxy config inline. Set a real bearer token and admin password
(`CHANGE-ME-BEARER-TOKEN`, `CHANGE-ME-ADMIN`), and swap the served
model if you don't want the default CodeGeeX4 GGUF. See that file's
header comment for the full "edit before use" list.

The config's origin is keyed to `model.local` (not this box's public
IP), so requests need a matching `Host:` header. See "Use it" below.

```bash
aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type g6.xlarge \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxx \
  --subnet-id subnet-xxxxxxxx \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=150,VolumeType=gp3}' \
  --user-data file://cloud-init.yaml \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=sbproxy-gpu-demo}]'
```

Watch the boot (bootstrap logs to `/var/log/sbproxy-bootstrap.log` on
the box, same as every other cloud this script runs on):

```bash
INSTANCE_ID="$(aws ec2 describe-instances \
  --filters 'Name=tag:Name,Values=sbproxy-gpu-demo' 'Name=instance-state-name,Values=running' \
  --query 'Reservations[-1].Instances[-1].InstanceId' --output text)"
PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

ssh -i your-key-pair.pem ubuntu@"$PUBLIC_IP" 'sudo tail -f /var/log/sbproxy-bootstrap.log'
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
ssh -i your-key-pair.pem -L 9090:localhost:9090 ubuntu@$PUBLIC_IP
# then open http://localhost:9090/admin/ui
```

## Public HTTPS

`cloud-init.yaml` serves plain HTTP only. For TLS without hand-rolling
Terraform, either put the box behind an Application Load Balancer or
CloudFront with TLS termination there, or edit the embedded config to
add sbproxy's own `acme:` block (see
[`sbproxy.yml.tftpl`](../terraform/l4-demo/sbproxy.yml.tftpl) for the
shape) and point a DNS record at the instance's public IP before the
ACME challenge can complete. The Terraform module in
[`deploy/terraform/l4-demo`](../terraform/l4-demo/README.md) does this
for you if you would rather not hand-edit YAML.

## Tear down

```bash
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
```

Cost: a `g6.xlarge` runs a little over $0.80/hr on demand in most
regions (check current pricing for your region), plus the boot volume.
Terminate the instance when you are done.

See [`self-hosting.md`](../../docs/self-hosting.md) and
[`admin.md`](../../docs/admin.md) for the model host and admin surface,
and [`use-case-serve-on-l4.md`](../../docs/use-case-serve-on-l4.md) for
the full config walkthrough this box's `serve:` block comes from.

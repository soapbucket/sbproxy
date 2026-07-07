# Serve Qwen, GLM, or Gemma on one cloud L4

*Last modified: 2026-07-07*

![sbproxy validate, plan, and doctor running the serve preflight for this page's config on a machine with no GPU](assets/use-case-serve-on-l4.gif)

*The recording shows the CPU half of this story: the preflight commands refusing a box with no GPU, which is exactly what they should do. The first-token half needs the L4 itself.*

You have GCP credits and a model you want to run on your own terms. The open-weight releases from Qwen, GLM, and Gemma are good enough for real work now, but most serving guides stop at a bare `vllm serve` with nothing in front of it and no plan for the day you need a hosted fallback. SBproxy is built for exactly this gap: "Call any model. Serve your own. Govern both." One Apache-2.0 binary routes to 66 providers or serves the weights on your own GPUs, and this page walks the serving half, from `gcloud compute instances create` to a first completion on a single NVIDIA L4.

A status note before you spend money. The model host is the newest part of SBproxy and is landing in phases. The released binary ships GPU discovery and managed weight download as default features, and the L4 in this guide is the reference card the whole path is certified against, by hand, at feature-complete points rather than by CI on every push. On a host with no GPU or no engine, a `serve:` block validates but starts no engine. Trust `sbproxy doctor` on your box over any document, including this one; [model-host.md](model-host.md) keeps the current status.

## What you will build

A `g2-standard-8` VM with one 24 GB L4, running an OpenAI-compatible gateway on port 8080. A `serve:` block names the official `Qwen/Qwen3-14B-GGUF` weights at `Q4_K_M`; SBproxy downloads them into its cache, launches llama-server as a supervised subprocess on a loopback port, and routes chat completions to it. That GGUF-plus-llama-server pairing is the path certified on this exact card; the catalog-id form, where the fit planner picks the quant for your card (FP8 on an Ada L4), takes over once catalog-driven serving lands. The same routing, guardrail, budget, and ledger planes that govern hosted providers apply to this local one, so the config you write here can grow a cloud spill lane later without rework.

## Prerequisites

- A GCP project with `gcloud` authenticated (`gcloud auth login`) and L4 quota (`NVIDIA_L4_GPUS`) in your target region. Check before you create anything:

  ```bash
  gcloud compute regions describe us-central1 \
    --format="value(quotas)" | tr ',' '\n' | grep -i l4
  ```

- A cost expectation. L4 boxes bill while they exist: the smaller `g2-standard-4` runs about $0.71/hr on demand, roughly $516 a month if you forget it. The delete command is at the end of this page. Use it.
- `curl` for sending requests, and `jq` if you like pretty JSON.
- Optional: a Hugging Face token. The Qwen weights in this walkthrough are ungated, but Gemma and Llama sit behind click-through licenses, and a gated repo needs `hf_token` in a model manifest (more on that below).

## Install

Create the VM. The Deep Learning image ships the CUDA driver preinstalled, so there is no driver dance on first boot:

```bash
gcloud compute instances create sbproxy-l4 \
  --zone=us-central1-a \
  --machine-type=g2-standard-8 \
  --accelerator=type=nvidia-l4,count=1 \
  --maintenance-policy=TERMINATE \
  --image-family=common-cu124-ubuntu-2204 \
  --image-project=deeplearning-platform-release \
  --boot-disk-size=200GB \
  --boot-disk-type=pd-ssd \
  --metadata=install-nvidia-driver=True

gcloud compute ssh sbproxy-l4 --zone=us-central1-a
```

The repo wraps these commands in `scripts/provision-l4.sh` (`up`, `ssh`, `down`) if you would rather not retype them, and [`deploy/terraform/l4-demo`](../deploy/terraform/l4-demo) is the Terraform version with a public IP, Let's Encrypt TLS, and a bearer token in front, for when this stops being an experiment.

On the box, put an inference engine on `PATH`. For the GGUF path this page walks, that is `llama-server`: grab the CUDA build for your platform from the [llama.cpp releases page](https://github.com/ggml-org/llama.cpp/releases) (the asset names are version-pinned, pick the `ubuntu` `cuda` zip), unzip it, and put `llama-server` somewhere on `PATH` such as `/usr/local/bin`. vLLM serves the safetensors path and installs with `uv tool install vllm`; it becomes the default for safetensors weights once that path is certified.

Then install SBproxy itself:

```bash
# Linux / macOS, single static binary:
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker:
docker pull ghcr.io/soapbucket/sbproxy:latest
```

The [manual](manual.md) covers checksums, packages, and the rest of the install matrix. SBproxy deliberately does not install engines for you; `sbproxy doctor` diagnoses a missing one and prints the manual steps.

## Minimal config

Save this as `sb.yml`. It is [`examples/use-case-serve-on-l4/sb.yml`](../examples/use-case-serve-on-l4/sb.yml), and its shape comes from [`examples/ai-local-serving`](../examples/ai-local-serving):

```yaml
proxy:
  http_bind_port: 8080

origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: local
          default_model: qwen3-14b
          models:
            - qwen3-14b
          serve:
            models:
              - model: "hf:Qwen/Qwen3-14B-GGUF:Q4_K_M"
                gguf_file: Qwen3-14B-Q4_K_M.gguf
                name: qwen3-14b
                extra_args: ["--jinja"]
                keep_alive: 30m
```

The `proxy` block binds the data plane to 8080. The origin key `ai.local` is the hostname clients address; on a private box a `Host:` header is enough, and the Terraform demo swaps in a real domain.

The provider is the interesting part. It has no `base_url`, and that is deliberate: a served provider is hosted on this box, the gateway resolves the engine's loopback port itself, and writing `base_url` next to `serve:` is rejected as a config error. The `default_model` and `models` list name the serve entry, and that name is the model id every plane sees: routing, budgets, virtual keys, the usage ledger.

Inside `serve:`, the model line names the weights explicitly: the Hugging Face repo, the quant, and the exact file. GGUF weights pick llama.cpp as the engine, `extra_args: ["--jinja"]` has llama-server apply the chat template embedded in the GGUF (Qwen3's turns render wrong without it), and `name:` is the model id every plane sees. `keep_alive: 30m` unloads an idle engine after thirty minutes so the VRAM comes back. The shorter form you will eventually write here is a bare catalog id (`model: qwen3-14b`), with the fit planner walking the quant list `[FP8, Q4_K_M]` and taking the first one the card can run: FP8 on this L4, the Q4 GGUF on a 16 GB T4 that has no FP8 kernels. That resolution ships with catalog-driven serving; today a bare catalog id fails at request time with `no model metadata`, so use the explicit form.

To serve GLM instead, point the model line at a GLM GGUF repo and file the same way. Gemma is not in the built-in catalog and its repos are gated, so give it a model manifest entry instead: one reviewable file that names the source repo, a pinned revision, per-file sha256 digests, a pull policy, and, for a gated repo, your Hugging Face token as an `hf_token` secret reference rather than a literal in config. Point `serve.catalog_file` at the manifest and name its entry in `serve.models`. A curated manifest with digests doubles as a supply-chain allowlist. See [`examples/model-manifest`](../examples/model-manifest) and the manifest section of [model-host.md](model-host.md).

One paragraph on why this config surface is shaped the way it is. Letting configuration start subprocesses inside a gateway that holds provider keys is a real attack surface, so it is constrained: `engine` is an allowlisted enum (`vllm`, `llama_cpp`), never a command string, the runtime owns the argument templates, engine binaries resolve from `PATH` or pinned releases only, and downloaded weights verify against manifest sha256 digests before an engine reads them. The full posture, including what is enforced today and what hardening remains, is in [security-model-host.md](security-model-host.md).

## Run it

Ask the box whether it qualifies before starting anything:

```console
$ sbproxy doctor
build capabilities
  gpu-nvidia      (GPU discovery for serve:)   yes
  model-weights   (managed weight download)    yes
  ...

gpus
  [0] NVIDIA L4  22 GiB total, 22 GiB free, compute 8.9, fp8 yes
  nvidia-smi: /usr/bin/nvidia-smi

inference engines on PATH
  vllm          not found
  llama-server  /usr/local/bin/llama-server
  container     not found (docker/podman)

model cache
  /var/lib/sbproxy/models

local model serving (serve:): ready
```

That is the verdict captured on the reference L4. The `fp8 yes` on the GPU line is the compute capability 8.9 the fit planner gates on. On a machine that does not qualify, the verdict flips to `not available` and lists every blocker with install steps, which is a better way to find out than a spawn failure at 2am.

Check the config itself with the plan differ. With no `--against` baseline, everything surfaces as added:

```console
$ sbproxy plan -f sb.yml
  + origins.ai.local [reload] origin 'ai.local' added

Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

Exit code 2 means valid with changes present; a config that fails validation exits 3 with the findings printed. The serve-specific rejections are enforced at gateway start, before the listener takes traffic: an engine outside the allowlist (`unknown variant 'sglang', expected one of 'auto', 'vllm', 'llama_cpp', 'embedded'`) or a `base_url` on a served provider is a fatal boot error with a message naming the fix.

Start the gateway:

```bash
sbproxy sb.yml
```

Send the first completion. Be patient with this one call: it pays the cold start, a managed download of the 9 GB GGUF into `/var/lib/sbproxy/models` plus the llama-server bring-up. On the reference L4 that first call answered in about four and a half minutes, and a later cold start with the weights already cached took 226 seconds; the gateway log shows the progress.

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Say hello from the L4."}]}'
{
  "choices": [{"finish_reason": "stop", "index": 0, "message": {"role": "assistant",
    "content": "A reverse proxy is a server that acts as an intermediary between clients and backend servers...",
    "reasoning_content": "Okay, the user asked..."}}],
  "id": "chatcmpl-...",
  "model": "/var/lib/sbproxy/models/Qwen/Qwen3-14B-GGUF/main/Qwen3-14B-Q4_K_M.gguf",
  "object": "chat.completion",
  "usage": {"prompt_tokens": 16, "completion_tokens": 235, "total_tokens": 251}
}
```

Two captured details worth reading twice. The `model` field currently names the served weights file rather than echoing `qwen3-14b`; a filesystem path there is unambiguous proof this box answered. And Qwen3 is a reasoning model: on the OpenAI wire its thinking arrives separately as `reasoning_content`, and it spends real tokens there, so give `max_tokens` room when you cap it.

Now look at what the runtime handed the engine:

```console
$ pgrep -af llama-server
70420 llama-server --model /var/lib/sbproxy/models/Qwen/Qwen3-14B-GGUF/main/Qwen3-14B-Q4_K_M.gguf --host 127.0.0.1 --port 39867 --ctx-size 131072 --n-gpu-layers 999 --jinja
```

The runtime owns that argv: the loopback bind, the cache path, full GPU offload. When catalog-driven serving lands, the quant on this line becomes the fit planner's decision, made from compute capability and free VRAM before the process ever spawns; on a T4 it refuses FP8 with `FP8 needs FP8 kernels but Tesla T4 (compute 7.5) has none` and falls through to `Q4_K_M`. The math behind that choice is in [gpu-fit-planning.md](gpu-fit-planning.md).

Send the same request a second time. It answers in normal API time, because the model is resident and stays that way for the `keep_alive` window.

## You are done when

- The completion returns `HTTP 200` with an OpenAI-shaped body whose `model` field names the served GGUF file and whose `usage.total_tokens` is present.
- `pgrep -af llama-server` on the box shows the Q4_K_M weights file and `--n-gpu-layers 999` in the engine argv.
- A second identical request completes in a small fraction of the first call's time (4.2 seconds against a 226-second cold start, on the reference L4).

Then stop the meter:

```bash
gcloud compute instances delete sbproxy-l4 --zone=us-central1-a --quiet
```

## Next steps

- [self-hosting.md](self-hosting.md) - the wider self-hosting story: cloud spill in the same fallback array, aliasing a hosted model name onto local weights, auth and budgets in front
- [model-host.md](model-host.md) - the reference for the catalog, the manifest, `keep_alive` and eviction, and the current phase status
- [gpu-fit-planning.md](gpu-fit-planning.md) - the capability tiers and the VRAM math the planner runs
- [model-host-certification.md](model-host-certification.md) - the certification procedure this page's provisioning steps come from, including the T4 refusal path
- [security-model-host.md](security-model-host.md) - the threat model for spawning engines from config
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and ledger planes the local model plugs into

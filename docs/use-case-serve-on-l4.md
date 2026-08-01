# Serve Qwen, GLM, or Gemma on one cloud L4

*Last modified: 2026-07-28*

![sbproxy validate, plan, and doctor running the serve preflight for this page's config on a machine with no GPU](assets/use-case-serve-on-l4.gif)

*The recording runs `sbproxy validate`, `plan`, and `doctor` for the
llama.cpp + GGUF config on a machine without a GPU. The NVIDIA L4 procedure
is [certified separately](#nvidia-l4) on real hardware.*

Use this guide when you want to serve open weights behind the same gateway
that routes to hosted providers. The runnable section uses llama.cpp and a
GGUF model on CPU or Apple Silicon. A later section gives the procedure for
certifying vLLM or SGLang on an NVIDIA L4.

NVIDIA single-GPU serving is certified on a real L4 as of 2026-07-30: a live
completion through the gateway on a digest-pinned vLLM container, truthful
status, and a stop that returned the device to 0 MiB. Multi-GPU and live
multi-node GCP certification remain open. See
[model-host-certification.md](model-host-certification.md) for the evidence
ledger and [model-host.md](model-host.md#managed-engines) for engine policy.

## What you will build

- **Runnable today:** Check the `serve:` config with `sbproxy validate`,
  `plan`, and `doctor`. If `llama-server` is available, send a real
  completion on CPU or Apple Metal.
- **Certified on real hardware:** Create a `g2-standard-8` VM with one 24 GB
  L4 and reproduce the recorded completion, status, and stop evidence through
  a digest-pinned vLLM container.

The same routing, guardrail, budget, and ledger planes that govern hosted providers apply to a local deployment either way.

## Prerequisites

For the stand-in you can run today:

- `curl` for sending requests, and `jq` if you like pretty JSON.
- `sbproxy` installed (below). `sbproxy doctor` tells you whether `llama-server` is already on this box or needs fetching before a real completion works.
- Optional: a Hugging Face token. The Qwen weights in this walkthrough are ungated, but Gemma and Llama sit behind click-through licenses, and a gated repo needs `hf_token` in a model manifest (more on that below).

The GCP project, L4 quota, and cost prerequisites for the NVIDIA path live in [NVIDIA L4](#nvidia-l4). You do not need any of that for the rest of this page.

## Install

```bash
# Prebuilt release executable for Linux amd64/arm64 (glibc) or Apple Silicon macOS.
# No Rust, Python, JVM, or Node toolchain/runtime is required.
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker:
docker pull soapbucket/sbproxy:latest
```

The [manual](manual.md) covers checksums, packages, and the rest of the install matrix. `sbproxy doctor` reports which engines resolve on `PATH` and, for a missing one, the acquisition paths viable on this host.

## Minimal config (stand-in)

Save this as `sb.yml`. It is [`examples/use-case-serve-on-l4/sb.yml`](../examples/use-case-serve-on-l4/sb.yml), and its shape comes from [`examples/ai-local-serving`](../examples/ai-local-serving). This config names llama.cpp and a GGUF file. This walkthrough tests that configuration on CPU and Apple Metal. SBproxy also supports digest-pinned CUDA llama.cpp source builds, but they are not the certified NVIDIA path for this guide. See [NVIDIA L4](#nvidia-l4) for that path.

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
                engine: llama_cpp
                keep_alive: 30m
```

The `proxy` block binds the data plane to 8080. The origin key `ai.local` is the hostname clients address; on a private box a `Host:` header is enough, and the Terraform demo swaps in a real domain.

The provider is the interesting part. It has no `base_url`, and that is deliberate: a served provider is hosted on this box, the gateway resolves the engine's loopback port itself, and writing `base_url` next to `serve:` is rejected as a config error. The `default_model` and `models` list name the serve entry, and that name is the model id every plane sees: routing, budgets, virtual keys, the usage ledger.

Inside `serve:`, the model line names the Hugging Face repository, quant,
and file. GGUF weights select llama.cpp. Setting `engine: llama_cpp` makes
that choice explicit instead of leaving it to `auto`. The `name` becomes
the model id used by routing, budgets, virtual keys, and the usage ledger.
`keep_alive: 30m` unloads the engine after thirty idle minutes.

The stable llama.cpp argument allowlist does not include
`extra_args: ["--jinja"]`. The engine therefore uses the GGUF's embedded
chat template. If Qwen3 turns render incorrectly, an operator cannot force
the Jinja template through this config today.

A bare catalog id such as `model: qwen3-14b` lets the fit planner select the
first compatible quant from `[FP8, Q4_K_M]`. FP8 requires a supported
NVIDIA GPU and vLLM; Q4 GGUF runs through llama.cpp on CPU or Metal. This
guide uses the explicit form to pin the weights file.

To serve GLM instead, point the model line at a GLM GGUF repo and file the same way. Gemma is not in the built-in catalog and its repos are gated, so give it a model manifest entry instead: one reviewable file that names the source repo, a pinned revision, per-file sha256 digests, a pull policy, and, for a gated repo, your Hugging Face token as an `hf_token` secret reference rather than a literal in config. Point `serve.catalog_file` at the manifest and name its entry in `serve.models`. A curated manifest with digests doubles as a supply-chain allowlist. See [`examples/model-manifest`](../examples/model-manifest) and the manifest section of [model-host.md](model-host.md).

One paragraph on why this config surface is shaped the way it is. Letting configuration start subprocesses inside a gateway that holds provider keys is a real attack surface, so it is constrained. `engine` is an allowlisted enum (`auto`, `vllm`, `sglang`, `llama_cpp`, `embedded`, or `mistralrs`), never a command string. The runtime owns typed argument templates and provisions each engine through its supported path: an operator binary, a verified release or source build, a pinned uv environment, or a digest-pinned container. Downloaded weights verify against manifest sha256 digests before an engine reads them. The full posture, including what is enforced today and what hardening remains, is in [security-model-host.md](security-model-host.md).

## Run it (stand-in)

Ask the box whether it qualifies before starting anything. This is exactly what the recording above shows. Here is the real, abbreviated report from an Apple Silicon Mac with no `llama-server` installed yet; run `sbproxy doctor` on your own box for its live report:

```console
$ sbproxy doctor
host
  macos / aarch64, 14 CPUs, 36 GiB RAM

gpus / memory budget
  [0] Apple M4 Max (Apple)  27 GiB budget, fp8 no
  metal: available

inference engines
  llama_cpp   not installed; sbproxy can fetch the pinned ggml-org llama.cpp macos-arm64 release binary
  vllm        not installed, no acquisition path on this host

model cache
  /Users/you/.cache/sbproxy/models  (302 GiB free)

local model serving (serve:): not available
  - no inference engine is installed yet (one can be acquired; see recommendation)
  recommended: llama_cpp: sbproxy can fetch the pinned ggml-org llama.cpp macos-arm64 release binary
```

A `not available` verdict names every blocker with a recommended fix, which is a better way to find out than a spawn failure at 2am. Once `llama-server` is present, either already on `PATH` or fetched from the pinned release, the verdict for `serve:` flips to `ready` and the completion below actually answers. `vllm`'s line is honest too: it names why it cannot be acquired on this host. This walkthrough keeps its GGUF on llama.cpp.

Check the config itself with the plan differ. With no `--against` baseline, everything surfaces as added:

```console
$ sbproxy plan -f sb.yml
  + origins.ai.local [reload] origin 'ai.local' added

Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

Exit code 2 means valid with changes present; a config that fails validation exits 3 with the findings printed. The serve-specific rejections are enforced at gateway start, before the listener takes traffic. An engine outside the allowlist (`unknown variant 'shell', expected one of 'auto', 'vllm', 'sglang', 'llama_cpp', 'embedded', 'mistralrs'`) or a `base_url` on a served provider is a fatal boot error with a message naming the fix. `validate` and `plan` going green is the part of this page that is true on every machine, GPU or none.

If `llama-server` is available on this box, go further and start the gateway:

```bash
sbproxy serve -f sb.yml
```

Send a completion. Be patient with this one on a cold cache: it pays a managed download of the 9 GB GGUF into `/var/lib/sbproxy/models` plus the llama-server bring-up, which can run several minutes on a laptop. The gateway log shows progress.

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Say hello in one short sentence."}]}'
{
  "choices": [{"finish_reason": "stop", "index": 0, "message": {"role": "assistant",
    "content": "Hello! Hope your day is going well.",
    "reasoning_content": "The user wants a short greeting..."}}],
  "id": "chatcmpl-...",
  "model": "/var/lib/sbproxy/models/Qwen/Qwen3-14B-GGUF/main/Qwen3-14B-Q4_K_M.gguf",
  "object": "chat.completion",
  "usage": {"prompt_tokens": 16, "completion_tokens": 41, "total_tokens": 57}
}
```

Two captured details worth reading twice. The `model` field currently names the served weights file rather than echoing `qwen3-14b`; a filesystem path there is unambiguous proof this box answered. And Qwen3 is a reasoning model: on the OpenAI wire its thinking arrives separately as `reasoning_content`, and it spends real tokens there, so give `max_tokens` room when you cap it.

Now look at what the runtime handed the engine:

```console
$ pgrep -af llama-server
70420 llama-server --model /var/lib/sbproxy/models/Qwen/Qwen3-14B-GGUF/main/Qwen3-14B-Q4_K_M.gguf --host 127.0.0.1 --port 39867 --ctx-size 131072 --n-gpu-layers 999
```

The runtime owns that argv: the loopback bind, the cache path, and however many GPU layers this host's llama.cpp build can offload (Apple Metal here, or zero on CPU-only). With a bare catalog id instead of an explicit model line, the quant on this line is the fit planner's decision, made from the host's compute capability before the process ever spawns. The math behind that choice is in [gpu-fit-planning.md](gpu-fit-planning.md).

Send the same request a second time. It answers in normal API time, because the model is resident and stays that way for the `keep_alive` window.

## You are done when

- `sbproxy validate sb.yml` exits 0 and `sbproxy plan -f sb.yml` reports the origin added. This is true on any machine, with or without a GPU.
- `sbproxy doctor` gives a clear, actionable verdict for this host: `ready` with `llama_cpp` resolved, or `not available` with the exact blocker and a suggested fix. Either outcome is a legitimate result for this stand-in.
- Optional, only if `llama-server` was actually available on this box: the completion above returns `HTTP 200` with an OpenAI-shaped body whose `model` field names the served GGUF file, and a second identical request completes in a small fraction of the first call's time because the model stayed resident.

## NVIDIA L4

This procedure has been run. A `g2-standard-8` with one L4 served a live
completion through the gateway on 2026-07-30, with a digest-pinned vLLM
container: 163 seconds cold including the weight pull, 0.109 seconds warm, and
a stop that returned the device from 9126 MiB to 0 MiB. The full record is in
[model-host-certification.md](model-host-certification.md). The steps below
reproduce it.

Prefer the digest-pinned container over a host `uv` or `pip` install. The
container packages the whole CUDA and Python environment; a host install
resolves to whatever vLLM is newest, then needs Python headers and a C
toolchain for the Triton JIT, and the cascade does not end.

What you need:

- A GCP project with `gcloud` authenticated (`gcloud auth login`) and L4 quota
  in your target region. Read **both** numbers: the per-region-per-type quota
  and the global one. Booting N devices needs both at N or above, and the
  global cap is set on the billing account rather than the project.

  ```bash
  gcloud compute regions describe us-central1 \
    --format="value(quotas)" | tr ',' '\n' | grep -i l4
  gcloud compute project-info describe \
    --format="value(quotas)" | tr ',' '\n' | grep -i GPUS_ALL_REGIONS
  ```

- A cost expectation. Google listed `g2-standard-8` at about $0.85 per hour
  on demand in `us-central1` on 2026-07-28, before disk and network charges.
  That is about $623 for 730 hours. Check the
  [current G2 price](https://cloud.google.com/products/compute/pricing/accelerator-optimized)
  before creating the VM, and use the delete command at the end.

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

The repo wraps these commands in `scripts/provision-l4.sh` (`up`, `ssh`,
`down`). [`deploy/terraform/l4-demo`](../deploy/terraform/l4-demo) adds a
public IP, Let's Encrypt TLS, and bearer authentication.

[model-host-certification.md](model-host-certification.md#provisioning-a-gpu-box-for-the-nvidia-lanes)
covers the same provisioning, and the recorded NVIDIA evidence sits beside
it. A run must prove device
detection, one-time artifact download, managed provisioning, completion,
status, drain-and-stop, and restart cache reuse.

`sbproxy doctor` already reports real hardware truthfully on an L4 box today; hardware discovery does not wait on the engine certification gate:

```console
$ sbproxy doctor
build capabilities
  gpu-nvidia      (NVIDIA discovery)            yes
  model-weights   (managed weight download)     yes
  ...

gpus / memory budget
  [0] NVIDIA L4 (NVIDIA)  22 GiB budget, fp8 yes, compute 8.9
  ...

inference engines
  llama_cpp   /usr/local/bin/llama-server
  vllm        not installed; ...

model cache
  /var/lib/sbproxy/models
...
```

The `fp8 yes` line reflects compute capability 8.9, which the fit planner
uses to gate FP8 under vLLM. `llama_cpp` may also resolve on this host, but
a llama.cpp completion does not certify the NVIDIA path. Certification
requires `engine: vllm` or `engine: sglang` and the live evidence listed
above.

Then stop the meter:

```bash
gcloud compute instances delete sbproxy-l4 --zone=us-central1-a --quiet
```

## Next steps

- [self-hosting.md](self-hosting.md) - the wider self-hosting story: cloud spill in the same fallback array, aliasing a hosted model name onto local weights, auth and budgets in front
- [model-host.md](model-host.md) - the reference for the catalog, the manifest, `keep_alive` and eviction, the managed engines, and the current phase status
- [gpu-fit-planning.md](gpu-fit-planning.md) - the capability tiers and the VRAM math the planner runs
- [model-host-certification.md](model-host-certification.md) - the evidence ledger and the certification procedure this page's NVIDIA L4 section comes from, including the T4 refusal path
- [security-model-host.md](security-model-host.md) - the threat model for spawning engines from config
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and ledger planes the local model plugs into

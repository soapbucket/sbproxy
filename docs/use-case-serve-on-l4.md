# Serve Qwen, GLM, or Gemma on one cloud L4

*Last modified: 2026-07-19*

![sbproxy validate, plan, and doctor running the serve preflight for this page's config on a machine with no GPU](assets/use-case-serve-on-l4.gif)

*The recording is the CPU/Metal stand-in this page actually runs today: `sbproxy validate`, `plan`, and `doctor` walking this page's llama.cpp + GGUF config on a machine with no GPU, refusing to start an engine it cannot serve. It is not NVIDIA L4 evidence — see [NVIDIA L4 (planned)](#nvidia-l4-planned) below for why, and for what the certified path looks like.*

You have GCP credits and a model you want to run on your own terms. The open-weight releases from Qwen, GLM, and Gemma are good enough for real work now, but most serving guides stop at a bare `vllm serve` with nothing in front of it and no plan for the day you need a hosted fallback. SBproxy is built for exactly this gap: "Call any model. Serve your own. Govern both." One Apache-2.0 binary routes to 66 providers or serves the weights on your own GPUs. This page has two halves: a `serve:` config plus preflight tooling you can run right now, on whatever CPU or Apple Silicon box you have open, and the planned procedure for the certified NVIDIA L4 path — from `gcloud compute instances create` to a first vLLM/SGLang completion — which is not yet backed by live hardware evidence.

A status note before you read further, and definitely before you spend money. Nothing below [NVIDIA L4 (planned)](#nvidia-l4-planned) has run on an L4. NVIDIA vLLM and SGLang container, multi-GPU, and multi-node GCP validation is reserved for the final integration PR; the deterministic driver and capacity suites run in CI today. Use [model-host-certification.md](model-host-certification.md) for the evidence ledger, and do not read the GGUF walkthrough below as proof of anything about NVIDIA GPUs — llama.cpp does not serve them. See [model-host.md](model-host.md#managed-engines) for the exact engine policy.

## What you will build

Two things, and only one of them is real yet:

- **Runnable today:** the `serve:` config below, checked with `sbproxy validate`, `plan`, and `doctor` on any machine, plus a real completion if that machine happens to have `llama-server` available (CPU or Apple Metal). This proves the config shape and the preflight tooling. It does not touch a GPU.
- **Planned:** a `g2-standard-8` VM with one 24 GB L4, running an OpenAI-compatible gateway on port 8080 through the certified vLLM or SGLang engine, using canonical managed deployments and exact catalog v2 artifacts, with completion, status, stop, and cache reuse recorded against real hardware. See [NVIDIA L4 (planned)](#nvidia-l4-planned).

The same routing, guardrail, budget, and ledger planes that govern hosted providers apply to a local deployment either way.

## Prerequisites

For the stand-in you can run today:

- `curl` for sending requests, and `jq` if you like pretty JSON.
- `sbproxy` installed (below). `sbproxy doctor` tells you whether `llama-server` is already on this box or needs fetching before a real completion works.
- Optional: a Hugging Face token. The Qwen weights in this walkthrough are ungated, but Gemma and Llama sit behind click-through licenses, and a gated repo needs `hf_token` in a model manifest (more on that below).

The GCP project, L4 quota, and cost prerequisites for the planned path live in [NVIDIA L4 (planned)](#nvidia-l4-planned) — you do not need any of that for the rest of this page.

## Install

```bash
# Linux / macOS, single static binary:
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker:
docker pull soapbucket/sbproxy:latest
```

The [manual](manual.md) covers checksums, packages, and the rest of the install matrix. `sbproxy doctor` reports which engines resolve on `PATH` and, for a missing one, the acquisition paths viable on this host.

## Minimal config (stand-in)

Save this as `sb.yml`. It is [`examples/use-case-serve-on-l4/sb.yml`](../examples/use-case-serve-on-l4/sb.yml), and its shape comes from [`examples/ai-local-serving`](../examples/ai-local-serving). This config names llama.cpp and a GGUF file, which is the CPU / Apple Metal engine path. Treat it as a stand-in for exercising the config shape and the preflight tooling — not as the NVIDIA GPU path. See [NVIDIA L4 (planned)](#nvidia-l4-planned) for what actually runs on the L4 itself.

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

Inside `serve:`, the model line names the weights explicitly: the Hugging Face repo, the quant, and the exact file. GGUF weights pick llama.cpp as the engine; `engine: llama_cpp` pins that explicitly rather than leaving it to `auto`, which matters once vLLM/SGLang exist alongside it. `name:` is the model id every plane sees, and `keep_alive: 30m` unloads an idle engine after thirty minutes so memory comes back. There is no `extra_args: ["--jinja"]` here: llama.cpp's stable argument allowlist does not include `--jinja` today, so the GGUF's embedded chat template goes through llama-server's own default handling rather than an operator override — worth knowing if Qwen3's turns render oddly, since forcing the Jinja template isn't a config knob yet. The shorter form is a bare catalog id (`model: qwen3-14b`): the catalog resolves it, the model metadata is prefetched at admission, and the fit planner walks the quant list `[FP8, Q4_K_M]`, taking the first one the card can run: FP8 on an NVIDIA GPU with FP8 kernels via vLLM, the Q4 GGUF on CPU or Metal via llama.cpp. The explicit form pins the exact weights file, which is why this walkthrough uses it.

To serve GLM instead, point the model line at a GLM GGUF repo and file the same way. Gemma is not in the built-in catalog and its repos are gated, so give it a model manifest entry instead: one reviewable file that names the source repo, a pinned revision, per-file sha256 digests, a pull policy, and, for a gated repo, your Hugging Face token as an `hf_token` secret reference rather than a literal in config. Point `serve.catalog_file` at the manifest and name its entry in `serve.models`. A curated manifest with digests doubles as a supply-chain allowlist. See [`examples/model-manifest`](../examples/model-manifest) and the manifest section of [model-host.md](model-host.md).

One paragraph on why this config surface is shaped the way it is. Letting configuration start subprocesses inside a gateway that holds provider keys is a real attack surface, so it is constrained: `engine` is an allowlisted enum (`vllm`, `llama_cpp`), never a command string, the runtime owns the argument templates, engine binaries resolve from `PATH` or pinned releases only, and downloaded weights verify against manifest sha256 digests before an engine reads them. The full posture, including what is enforced today and what hardening remains, is in [security-model-host.md](security-model-host.md).

## Run it (stand-in)

Ask the box whether it qualifies before starting anything — this is exactly what the recording above shows. Here is the real, abbreviated report from an Apple Silicon Mac with no `llama-server` installed yet; run `sbproxy doctor` on your own box for its live report:

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

A `not available` verdict names every blocker with a recommended fix, which is a better way to find out than a spawn failure at 2am. Once `llama-server` is present, either already on `PATH` or fetched from the pinned release, the verdict for `serve:` flips to `ready` and the completion below actually answers. `vllm`'s line is honest too: it names why it cannot be acquired here rather than pretending it could serve this GGUF — it never does, on any host.

Check the config itself with the plan differ. With no `--against` baseline, everything surfaces as added:

```console
$ sbproxy plan -f sb.yml
  + origins.ai.local [reload] origin 'ai.local' added

Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

Exit code 2 means valid with changes present; a config that fails validation exits 3 with the findings printed. The serve-specific rejections are enforced at gateway start, before the listener takes traffic: an engine outside the allowlist (`unknown variant 'sglang', expected one of 'auto', 'vllm', 'llama_cpp', 'embedded'`) or a `base_url` on a served provider is a fatal boot error with a message naming the fix. `validate` and `plan` going green is the part of this page that is true on every machine, GPU or none.

If `llama-server` is available on this box, go further and start the gateway:

```bash
sbproxy sb.yml
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

- `sbproxy validate sb.yml` exits 0 and `sbproxy plan -f sb.yml` reports the origin added — true on any machine, with or without a GPU.
- `sbproxy doctor` gives a clear, actionable verdict for this host: `ready` with `llama_cpp` resolved, or `not available` with the exact blocker and a suggested fix. Either outcome is a legitimate result for this stand-in.
- Optional, only if `llama-server` was actually available on this box: the completion above returns `HTTP 200` with an OpenAI-shaped body whose `model` field names the served GGUF file, and a second identical request completes in a small fraction of the first call's time because the model stayed resident.

None of the above is NVIDIA L4 evidence. That gate is separate and is not closed yet — see below.

## NVIDIA L4 (planned)

This is the procedure for the certified path, and the status is exactly what [model-host-certification.md](model-host-certification.md) records: NVIDIA CUDA single node is *pending final GCP PR*. Deterministic T4/L4 descriptors, vLLM plans, and container isolation tests exist and run in CI; no live completion, status, or cache-reuse evidence from a real L4 has been recorded. Live GCP validation is reserved for the final integration PR.

The certified NVIDIA GPU engines are vLLM and SGLang, both launched as digest-pinned containers (vLLM can also use a pinned uv environment). **llama.cpp is not part of this path** — it serves GGUF models on CPU and Apple Metal, not on NVIDIA GPUs. See [model-host.md](model-host.md#managed-engines) for the exact policy. Concretely: the stand-in above, and a `pgrep -af llama-server` showing an engine running on an L4 box, are not NVIDIA L4 evidence, no matter what GPU happens to be attached to that box.

When you want to work through the planned procedure yourself:

- A GCP project with `gcloud` authenticated (`gcloud auth login`) and L4 quota (`NVIDIA_L4_GPUS`) in your target region. Check before you create anything:

  ```bash
  gcloud compute regions describe us-central1 \
    --format="value(quotas)" | tr ',' '\n' | grep -i l4
  ```

- A cost expectation. L4 boxes bill while they exist: the smaller `g2-standard-4` runs about $0.71/hr on demand, roughly $516 a month if you forget it. The delete command is at the end of this section. Use it.

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

The repo wraps these commands in `scripts/provision-l4.sh` (`up`, `ssh`, `down`) if you would rather not retype them, and [`deploy/terraform/l4-demo`](../deploy/terraform/l4-demo) is the Terraform version with a public IP, Let's Encrypt TLS, and a bearer token in front, for when this stops being an experiment. [model-host-certification.md](model-host-certification.md#final-gcp-nvidia-gate) walks the same provisioning through `scripts/provision-l4.sh`, plus the certification gate itself: a config naming the vLLM engine and a placeholder model — deliberately not a working config yet, since the certified model and variant are not pinned until that PR lands — the digest-pinned container repeat, and the checks a real run must prove: device detection, a one-time artifact download, managed uv provisioning, a real completion, full status shape, drain-and-stop, and restart cache reuse.

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

The `fp8 yes` on the GPU line reflects the compute capability 8.9 the fit planner gates on for vLLM. `llama_cpp` resolving here is real too, and that is exactly why this policy needs saying out loud: an L4 box with `llama-server` on `PATH` can technically boot the stand-in config from this page and answer a completion through llama.cpp. That is not the certified NVIDIA path, is not evidence for the table in [model-host-certification.md](model-host-certification.md), and should not appear in a done-when for this box. The certified path is `engine: vllm` or `engine: sglang` against a digest-pinned container, proven with the checklist above, once the final integration PR closes that gate.

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

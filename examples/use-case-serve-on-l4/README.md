# Serve a model on one cloud L4

*Last modified: 2026-07-19*

![Serve a model on one cloud L4](../../docs/assets/use-case-serve-on-l4.gif)

The config for the story doc
[docs/use-case-serve-on-l4.md](../../docs/use-case-serve-on-l4.md): a
provider with no `base_url` and a one-model `serve:` block.

**This is a CPU/Apple Metal stand-in, not an NVIDIA L4 demo.** The
config names llama.cpp and a GGUF file, which is the CPU/Metal engine
path. On any host with `llama-server` on `PATH` (or fetchable), the
gateway pulls the pinned Q4_K_M GGUF for `qwen3-14b` from Hugging Face,
spawns the pinned `llama_cpp` engine, and serves OpenAI-shaped completions
on port 8080. On a host without an engine it still boots and validates,
starts no engine, and logs the blocker — that preflight is what the GIF
above shows. It does not exercise or certify the NVIDIA GPU engine
path: that is vLLM/SGLang, still pending live GCP evidence (see
[docs/model-host.md#managed-engines](../../docs/model-host.md#managed-engines)
and
[docs/model-host-certification.md](../../docs/model-host-certification.md)).
Running this config on a box that happens to have an NVIDIA GPU does
not change that — llama.cpp does not serve NVIDIA GPUs.

## Run

```bash
# Directly (on any machine):
sbproxy sb.yml

# Or containerized (gateway surface only; see docker-compose.yml):
docker compose up
```

## What to expect

Preflight on any machine, GPU or none:

```bash
sbproxy validate sb.yml
# ok: sb.yml is a valid sbproxy config

sbproxy plan -f sb.yml
#   + origins.ai.local [reload] origin 'ai.local' added
#
# Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

`sbproxy doctor` gives the host verdict: `local model serving (serve:):
ready` once `llama_cpp` resolves (already on `PATH`, or fetched from
the pinned b9905 release), or `not available` with the blockers listed
on a box that cannot serve yet.

Try it — chat completions, once an engine is available:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Say hello in one short sentence."}]}'
```

The first call pays the weight download and engine bring-up (can be
several minutes on a cold cache); the second returns in normal API
time because the model stays resident for `keep_alive: 30m`. Confirm
which engine actually answered:

```bash
pgrep -af llama-server
```

shows the Qwen3-14B Q4_K_M GGUF and the pinned `llama_cpp` engine's own
argv from `sb.yml`. This confirms the CPU/Metal stand-in worked; it
says nothing about NVIDIA L4 readiness.

## GPU caveats

- If this box has an NVIDIA GPU, `sbproxy doctor` will detect it
  (that hardware discovery already works), but this config still runs
  through llama.cpp on CPU, not through the GPU. NVIDIA serving is a
  separate, not-yet-certified engine path (vLLM/SGLang) — see the
  story doc's "NVIDIA L4 (planned)" section.
- If no engine is available at all, `validate` and `plan` still pass;
  only the completion and `pgrep` steps above are skipped, and
  `doctor` explains why.

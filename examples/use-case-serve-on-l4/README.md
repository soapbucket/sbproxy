# Serve a model on one cloud L4

*Last modified: 2026-07-09*

![Serve a model on one cloud L4](../../docs/assets/use-case-serve-on-l4.gif)

The config for the story doc
[docs/use-case-serve-on-l4.md](../../docs/use-case-serve-on-l4.md): a
provider with no `base_url` and a one-model `serve:` block. On a GPU
host with `llama-server` on `PATH`, the gateway pulls the pinned
Q4_K_M GGUF for `qwen3-14b` from Hugging Face, spawns the engine with
`--jinja`, and serves OpenAI-shaped completions on port 8080. On a host
without a GPU it still boots and validates, but starts no engine and
logs the blocker; that preflight is worth seeing on its own.

## Run

```bash
# Directly (on the L4 box, per the story doc):
sbproxy sb.yml

# Or containerized (gateway surface only; see docker-compose.yml):
docker compose up
```

## What to expect

Preflight on any machine:

```console
$ sbproxy validate sb.yml
ok: sb.yml is a valid sbproxy config

$ sbproxy plan -f sb.yml
  + origins.ai.local [reload] origin 'ai.local' added

Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

`sbproxy doctor` gives the host verdict: `local model serving (serve:):
ready` on the L4, or `not available` with the blockers listed on a box
that cannot serve. On the L4, the first completion pays the weight
download and engine bring-up (minutes), the second returns in normal
API time, and `pgrep -af llama-server` shows the Qwen3-14B Q4_K_M
GGUF and `--jinja` in the engine argv, the pinned weights and
chat-template flag from `sb.yml`.

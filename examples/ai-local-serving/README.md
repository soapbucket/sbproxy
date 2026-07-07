# AI gateway that hosts the model locally

*Last modified: 2026-07-04*

Most AI-gateway examples proxy to a model server you already run. This
one turns the gateway into the host: a provider's `serve:` block names
models the gateway itself resolves, fits to the local GPU, spawns, and
supervises, then registers as a local provider ahead of any cloud
fallback. It is the local-inference wedge from the model-host work
(see [`docs/model-host.md`](../../docs/model-host.md)).

## Status

This example exercises the model-host **config surface and catalog**:
the `serve:` block, catalog-id resolution, the engine allowlist, and
the eviction policy. The engine-spawn and GPU-fit **lifecycle** ships
in later phases of the epic and needs a GPU to run. On a CPU-only or
engine-less host the block parses and validates but starts no engine,
so this config is for reading and validation, not an end-to-end local
completion yet.

## Run

```bash
make run CONFIG=examples/ai-local-serving/sb.yml
```

## What this exercises

- `providers[].serve:` - the model-host block on an `ai_proxy` provider.
- Catalog id resolution (`qwen3-14b`) and an explicit
  `hf:Qwen/Qwen3-8B-GGUF:Q4_K_M` reference that bypasses the catalog.
- The engine allowlist (`vllm`, `llama_cpp`); an unknown engine is a
  config error, never an arbitrary command.
- `keep_alive` per model and an `eviction: lru` host policy.
- No address anywhere: a served provider carries no `base_url`, so the
  gateway resolves the engine's loopback port itself.
  Writing `base_url` alongside `serve:` is now a config error;
  `base_url` + `allow_private_base_url` stay only for a
  separately-running engine (an unmanaged Ollama, a remote vLLM box).

## What proves the config is right

- `sbproxy plan -f sb.yml` accepts it (the `serve:` block validates,
  the engines are on the allowlist, the catalog ids resolve).
- Point a second provider at a cloud model and the local models sort
  ahead of it in the fallback array (local-first).

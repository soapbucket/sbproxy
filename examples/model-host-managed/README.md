# Managed local model

*Last modified: 2026-07-10*

This example runs the built-in pinned Qwen bootstrap artifact through the
canonical single-node model host. `proxy.model_host` owns the deployment;
`provider_type: managed_model` exposes it as the client model `qwen` on both
loopback hostnames.

## Validate and pre-pull

Set a real admin password before loading the file:

```bash
export SB_ADMIN_PASSWORD="$(openssl rand -hex 32)"
sbproxy validate examples/model-host-managed/sb.yml
sbproxy models pull -f examples/model-host-managed/sb.yml --format json
```

The pull command selects the canonical deployment, uses its exact variant and
engine, writes to `./.cache/sbproxy-models`, and applies the configured cache
budget. It verifies the artifact but starts no engine.

## Start the gateway

```bash
sbproxy serve -f examples/model-host-managed/sb.yml
```

Startup prepares the artifact, provisions the pinned llama.cpp engine, and
warms `local-qwen` before publishing the request pipeline.

Send a completion from another terminal:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"qwen","messages":[{"role":"user","content":"hello"}]}'
```

## Inspect and stop

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090
export SB_ADMIN_USERNAME=admin

sbproxy models ps --format json
sbproxy models stop local-qwen --format json
```

The stop command drains active requests and stops the engine. It leaves the
verified Qwen artifact in the cache.

## Change the deployment

Edit the deployment in `sb.yml`, then use the normal reload transaction:

```bash
sbproxy apply -f examples/model-host-managed/sb.yml
```

The runtime prepares the complete candidate before swapping routes. If the new
artifact, engine, or capacity check fails, the current `local-qwen` generation
keeps serving.

## Hardware note

The GGUF variant supports CPU, Apple Metal, and CUDA workers. Apple Metal is the
real hardware gate for this PR. Live NVIDIA and multi-node GCP validation is
reserved for the final integration PR.

See [`docs/model-host.md`](../../docs/model-host.md) for the full field reference
and [`docs/security-model-host.md`](../../docs/security-model-host.md) for the
process and artifact trust boundaries.

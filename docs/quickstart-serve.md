# Run your first managed model

*Last modified: 2026-07-10*

Install SBproxy, then run the pinned bootstrap model from the built-in catalog:

```bash
curl -fsSL https://download.sbproxy.dev | sh
sbproxy run qwen2.5-0.5b-instruct --variant q4_k_m
```

`sbproxy run` detects the worker, resolves the exact GGUF artifact, verifies its
size and SHA-256, provisions the matching llama.cpp engine, and warms the model.
It does not print a success banner while an engine is still downloading or
starting.

When the deployment reports `ready`, the output includes lines like these:

```text
qwen2.5-0.5b-instruct is ready on http://127.0.0.1:8080
Admin: http://127.0.0.1:<generated-port>
Admin username: admin
Admin password: <generated-password>
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=local
```

The generated admin password is high entropy and the admin listener binds to
loopback. Keep that terminal output if you want to use lifecycle commands during
the run.

## Send a completion

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"qwen2.5-0.5b-instruct","messages":[{"role":"user","content":"hello"}]}'
```

An OpenAI-compatible SDK can use the two exported variables from the ready
banner. `OPENAI_API_KEY=local` satisfies SDKs that require a nonempty value; it
is separate from the generated admin credential.

## Inspect and stop the deployment

Copy the generated admin URL and password into environment variables:

```bash
export SB_ADMIN_URL=http://127.0.0.1:49123
export SB_ADMIN_USERNAME=admin
export SB_ADMIN_PASSWORD='paste-generated-password'

sbproxy models ps --format json
sbproxy models stop local --format json
```

`models stop` drains active requests, stops the engine process, and leaves the
verified artifact in cache. A later start reuses it.

## Inspect without starting

`--dry-run` prints the generated canonical configuration and exits. It still
resolves the model against the actual worker, and it embeds a newly generated
admin credential in the printed file.

```bash
sbproxy run qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --port 8080 \
  --admin-port 9090 \
  --dry-run
```

Use `sbproxy doctor` and `sbproxy models list` for read-only host and catalog
inspection:

```bash
sbproxy doctor --format json
sbproxy models list --format json
sbproxy models show qwen2.5-0.5b-instruct --format json
```

## Hardware status

The bootstrap GGUF supports CPU, Apple Metal, and CUDA catalog workers. This PR
runs a real Apple Silicon request before publication. NVIDIA discovery, managed
vLLM, and the CUDA llama.cpp build have deterministic coverage, while the live
GCP NVIDIA and multi-node gate remains in the final integration PR.

If the selected artifact does not fit, the command exits before claiming the
endpoint is ready. Use a smaller variant, free device memory, or configure a
different worker.

## Move to a managed config

`sbproxy run` is a single-deployment convenience command. Use
[`examples/model-host-managed`](../examples/model-host-managed) when you need a
stable cache path, fixed admin port, queue limits, reload, or more than one
origin. [model-host.md](model-host.md) explains every field and the migration
from provider `serve:` blocks.

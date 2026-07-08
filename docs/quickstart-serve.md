# Run your first model in 60 seconds

*Last modified: 2026-07-07*

Two commands take a bare box to a served model with an OpenAI-compatible
endpoint. Install the binary, then run a model.

```bash
curl -fsSL https://download.sbproxy.dev | sh
sbproxy run hf:Qwen/Qwen2.5-0.5B-Instruct-GGUF \
  --name qwen --gguf-file qwen2.5-0.5b-instruct-q4_k_m.gguf
```

The first line downloads the sbproxy binary. The second one serves the
model. It detects your hardware, plans a fit, downloads the weights, and,
if you have no inference engine installed, fetches one. Then it serves on
`http://127.0.0.1:8080`. The download and the engine fetch happen on the
first request, so give it a minute the first time.

Send it an OpenAI-shaped request:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"qwen","messages":[{"role":"user","content":"hello"}]}'
```

## It works on any box

The same command runs on a Linux GPU server, an Apple Silicon Mac, or a
plain CPU box. sbproxy detects what it is running on and picks a path:

- An NVIDIA GPU: it uses the GPU. GGUF models run on llama.cpp and
  safetensors models run on vLLM, and sbproxy provisions both for you
  (llama.cpp is a fetched binary; vLLM runs through `uv`, which sbproxy
  also fetches). See [model-host.md](model-host.md) for the engines.
- An Apple Silicon Mac: it uses Metal and unified memory, with llama.cpp.
- A CPU-only box: it serves small models against a slice of system RAM.

It picks a quant that fits the memory it found. If nothing fits, it says
so up front and names why, at config load, so you find out before the
first request instead of after it.

## Pick a model

`sbproxy run` takes a catalog id or an explicit Hugging Face reference. A
GGUF repo needs `--gguf-file` (the exact file), since a GGUF-only repo
carries no `config.json` for the planner to read:

```bash
# A GGUF model on any box (llama.cpp, fetched for you):
sbproxy run hf:Qwen/Qwen2.5-0.5B-Instruct-GGUF \
  --name qwen --gguf-file qwen2.5-0.5b-instruct-q4_k_m.gguf

# A catalog id on a GPU box (safetensors, served by vLLM via uv):
sbproxy run qwen3-14b
```

On an NVIDIA GPU box, a safetensors model needs a C toolchain and the
Python headers (`build-essential`, `python3-dev`) for vLLM's runtime
compile step. GGUF models on llama.cpp need neither.

Flags override the port, engine, acceleration, and cache directory. Add
`--dry-run` to see the config and the resolution without serving.

## Check the box first

Two read-only commands tell you what a box can do before you run
anything:

```bash
sbproxy doctor        # OS, GPU or memory budget, engines, and how to serve
sbproxy models        # one row per catalog model with a per-GPU fit verdict
```

When a model has no way to run, `sbproxy doctor` names the one thing to
install and the exact command to install it.

## Where to go next

- [self-hosting.md](self-hosting.md) for a real `serve:` config, the model
  manifest, aliases, and spilling over to cloud providers.
- [model-host.md](model-host.md) for the catalog, the fit planner, and the
  engine supervisor.
- [configuration.md](configuration.md) for the full config schema.

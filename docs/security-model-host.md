# Model host security

*Last modified: 2026-07-10*

The model host lets configuration start inference-engine subprocesses
inside a gateway that also holds provider API keys. Spawning processes
from config is a real attack surface, so it is constrained
deliberately. This page states the posture, what the config surface
guarantees, what the shipped engine-spawn phase enforces, and the
hardening that remains. It mirrors the review done for unsandboxed ONNX
model parsing.

## Threat model

The attacker we care about is whoever can influence the `serve:`
config or the weights it points at: a compromised config source, a
malicious model repo, or a supply-chain swap of an engine binary. The
gateway process holds outbound provider credentials, so the worst
outcome is arbitrary code execution in that process's context or
exfiltration of those keys. The controls below aim to make config
unable to name an arbitrary executable and to make weights and engine
binaries verifiable.

## What the config surface guarantees today

These hold in the shipped config layer and are covered by unit tests
in `sbproxy-model-host::config`:

- **No arbitrary command.** There is no `cmd:`, `command:`,
  `program:`, `binary:`, `exec:`, or `shell:` field anywhere in the
  `serve:` block. The only executable-selecting key is `engine`, an
  allowlisted enum (`vllm`, `llama_cpp`, `embedded`). Config chooses
  among a fixed set; it cannot introduce a new executable. `embedded`
  spawns no subprocess at all (it runs in-process), so it removes the
  spawn surface rather than adding to it.
- **Fixed engine-to-binary mapping.** Each `EngineKind` resolves to
  one hard-coded binary name (`vllm`, `llama-server`); `embedded` maps
  to no external binary. There is no config path that supplies or
  overrides the binary name.
- **No shell.** `extra_args` entries are opaque argv values, stored
  and passed one element at a time. Shell metacharacters (`$(...)`,
  `;`, `&&`, redirects) are inert data because no shell ever
  interprets them; the runtime spawns the program directly with an
  argument vector, not a command line.
- **Unknown fields do not silently pass.** An unrecognized engine
  value is a config error, not a fallthrough.

This is the entire executable-selecting surface a config gets. The
shape matches [`examples/ai-local-serving`](../examples/ai-local-serving):

```yaml
serve:
  eviction: lru
  models:
    - model: qwen2.5-0.5b-instruct
      variant: q4_k_m       # exact catalog v2 artifact
      engine: llama_cpp     # allowlisted: vllm, llama_cpp, or embedded
                            # (default `auto` resolves to one of these at boot)
      keep_alive: 30m
      extra_args:           # one argv element per entry; a `$(...)` or `;`
        - "--max-model-len" # inside a value is inert data because no
        - "8192"            # shell ever parses the line
```

Writing `engine: run-my-script` fails the config load. There is no
field anywhere in the block that names a program.

## What the shipped engine-spawn phase enforces

The runtime launcher (`ProcessEngineLauncher`) has landed and been
certified on a real NVIDIA L4. The review of that surface:

- **Binary resolved from `PATH` or a pinned release only, never from
  config.** `EngineKind::binary_name` is the only source of the program
  name; there is no config path that supplies one. The optional
  auto-fetch (`llama_release`) downloads a pinned ggml-org release for
  the host platform and refuses an unpinned tag (no `latest`); a fetched
  release is sha256-verified before use.
- **Exact artifacts become visible atomically.** Catalog v2 resolution
  pins source revision, file paths, byte lengths, and SHA-256 digests.
  The manager stages partials under an artifact lock, resumes only when
  all validators still match, verifies every file, then atomically
  publishes an immutable snapshot. The managed launcher receives only
  that local snapshot. A mismatch leaves no ready artifact and no
  repository fallback.
- **Unsafe formats fail closed.** Safetensors and GGUF are preferred.
  Pickle requires explicit logical-model opt-in and opcode scanning
  before finalization.
- **Credentials are transport-only.** Source credentials are redacted
  from formatting, zeroized on drop, and never serialized into cache,
  resume, or durable-job metadata.
- **The engine process tree is reaped, and the gateway is never
  killed.** vLLM forks `EngineCore` workers that hold VRAM. Eviction and
  shutdown are graceful-first: `SIGTERM` lets the engine tear down its
  own workers, and only if it does not exit does a `SIGKILL` backstop
  fire, guarded so it targets **only a process group the child truly
  leads and that is distinct from the gateway's own group**. The L4
  certification caught an earlier form of this that could `SIGKILL` the
  gateway's own group; that is fixed and regression-tested. A crashed
  engine also fails fast (readiness is raced against the child exiting)
  with its captured stderr, so a broken model cannot hang a request for
  the full retry budget.
- **The loopback exception stays narrow.** A served provider carries no
  `base_url`; `serve:` and `base_url` on one provider is a config error,
  rejected at `plan` time. `allow_private_base_url` remains only for a
  separately-running external engine, and does not widen the SSRF guard
  for any other upstream.
- **Container images are pinned.** An `engines:` container launch is
  rejected at `plan` time unless it names a tagged/digest image (no
  `latest`, no untagged).

### Pinning weights in the manifest

The model manifest is where the digest pins live: each entry names its
source, pins a revision, and carries per-file sha256 digests, so a
curated manifest doubles as a supply-chain allowlist. This stanza is
from [`examples/model-manifest`](../examples/model-manifest), an
air-gapped model whose weights never touch the network but still
verify before the engine reads them:

```yaml
schema_version: 2
catalog_revision: operator-catalog-2026-07-10
models:
  offline-coder:
    params: 30B-A3B
    license: apache-2.0
    family: qwen
    context_length: 32768
    pull: manual
    variants:
      - id: q4_k_m
        format: gguf
        quant: Q4_K_M
        engines: [llama_cpp]
        source: file:/var/lib/sbproxy/weights/offline-coder/model.gguf
        revision: approved-transfer-42
        files:
          - path: model.gguf
            sha256: 0000000000000000000000000000000000000000000000000000000000000000
            size_bytes: 1 # replace with the approved file's exact size
        requirements:
          accelerators: [cpu, metal, cuda]
          min_memory_bytes: 19327352832
        stability: preview
        certification: operator-approval-required
```

Point `serve.catalog_file` at the manifest, then run `sbproxy models
pull offline-coder --variant q4_k_m --offline`. A file whose size or
digest differs never becomes ready. For an explicit gated pull, provide
`HF_TOKEN` or `HUGGING_FACE_HUB_TOKEN`; runtime secret-reference wiring
is not yet a stable capability, so pre-pull gated artifacts.

### Remaining hardening (not yet enforced)

- **Resource-bound the child.** cgroup memory/CPU limits (Linux) and
  dropping ambient privileges are not applied yet; a compromised engine
  currently runs with the gateway's privileges. Track before a
  multi-tenant deployment where an untrusted party controls the weights.
- **Retire legacy acquisition.** Raw `hf:` and catalog v1 serving remain
  preview compatibility paths. They do not carry exact sizes and must
  not be treated as equivalent to catalog v2 managed artifacts.

## Related

- [model-host.md](model-host.md) - the subsystem this secures.
- [local-inference.md](local-inference.md) - the ONNX sidecar
  precedent, isolated in its own process for the same reason.

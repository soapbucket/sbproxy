# Model host security

*Last modified: 2026-07-05*

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
  allowlisted enum (`vllm`, `llama_cpp`). Config chooses among a fixed
  set; it cannot introduce a new executable.
- **Fixed engine-to-binary mapping.** Each `EngineKind` resolves to
  one hard-coded binary name (`vllm`, `llama-server`). There is no
  config path that supplies or overrides the binary name.
- **No shell.** `extra_args` entries are opaque argv values, stored
  and passed one element at a time. Shell metacharacters (`$(...)`,
  `;`, `&&`, redirects) are inert data because no shell ever
  interprets them; the runtime spawns the program directly with an
  argument vector, not a command line.
- **Unknown fields do not silently pass.** An unrecognized engine
  value is a config error, not a fallthrough.

## What the shipped engine-spawn phase enforces

The runtime launcher (`ProcessEngineLauncher`) has landed and been
certified on a real NVIDIA L4. The review of that surface:

- **Binary resolved from `PATH` or a pinned release only, never from
  config.** `EngineKind::binary_name` is the only source of the program
  name; there is no config path that supplies one. The optional
  auto-fetch (`llama_release`) downloads a pinned ggml-org release for
  the host platform and refuses an unpinned tag (no `latest`); a fetched
  release is sha256-verified before use.
- **Weights verified before use.** The weight manager checks downloaded
  files against the manifest/catalog sha256 (`weights::verify_sha256`),
  and the supply-chain layer prefers safetensors and gates pickle
  weights. A mismatch aborts the launch.
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

### Remaining hardening (not yet enforced)

- **Resource-bound the child.** cgroup memory/CPU limits (Linux) and
  dropping ambient privileges are not applied yet; a compromised engine
  currently runs with the gateway's privileges. Track before a
  multi-tenant deployment where an untrusted party controls the weights.

## Related

- [model-host.md](model-host.md) - the subsystem this secures.
- [local-inference.md](local-inference.md) - the ONNX sidecar
  precedent, isolated in its own process for the same reason.

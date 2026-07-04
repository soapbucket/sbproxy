# Model host security

*Last modified: 2026-07-04*

The model host lets configuration start inference-engine subprocesses
inside a gateway that also holds provider API keys. Spawning processes
from config is a real attack surface, so it is constrained
deliberately. This page states the posture, what the config surface
guarantees today, and what the engine-spawn phase must still enforce
when it lands. It mirrors the review done for unsandboxed ONNX model
parsing.

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

## What the engine-spawn phase must enforce

The runtime launcher (the `EngineLauncher` implementation that spawns
the real process) is not in this slice. When it lands it must:

- **Resolve the binary from `PATH` or a pinned release only.** Never
  from a config-supplied path. A pinned release is verified against a
  checked-in sha256 before execution.
- **Verify weights.** Downloaded weights are checked against a sha256
  from the catalog (or the Hugging Face commit hash) before they are
  handed to an engine. A hash mismatch aborts the launch.
- **Kill the whole process tree.** vLLM forks worker processes that
  hold VRAM; eviction and shutdown must reap the entire tree
  (`PR_SET_PDEATHSIG` / process-group kill), not just the parent, or a
  leaked worker keeps the GPU and the keys' host busy.
- **Bound the child.** Apply cgroup memory/CPU limits (Linux) and drop
  ambient privileges so a compromised engine cannot escalate.
- **Keep the loopback exception narrow.** The engine binds loopback
  and the provider `base_url` points at it under
  `allow_private_base_url`; that opt-in must not widen the SSRF guard
  for any other upstream.

## Related

- [model-host.md](model-host.md) - the subsystem this secures.
- [local-inference.md](local-inference.md) - the ONNX sidecar
  precedent, isolated in its own process for the same reason.

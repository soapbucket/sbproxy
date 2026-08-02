# Custom engines

*Last modified: 2026-07-18*

The model host launches a short list of engines it knows by name: llama.cpp,
vLLM, and SGLang. Operators ask for more. TensorRT-LLM for NVIDIA-tuned
serving, Kokoro for speech, a container built in-house. This page records the
decision about how a new engine gets in, and why the answer is not a config
field that takes an image and a command line.

## The question

The obvious design is the one GPUStack ships: the operator names an arbitrary
image and a command template, the runtime substitutes the model path and port,
and runs whatever comes out. That covers every engine on day one. It is also
remote code execution by config: anyone who can write the YAML can run any
program with the GPU, the artifact cache, and the gateway's network identity.
[security-model-host.md](security-model-host.md) treats config writers as
privileged, but privileged is not unlimited, and every invariant on that page
assumes the runtime, not the config, decides what argv runs.

## The decision: keep the typed-driver seam

A new engine enters SBproxy as a first-party typed driver, not as
operator-supplied argv. The SGLang driver is the template. A driver declares
its capabilities (artifact formats, accelerators, container and uv support),
detects what is installed or acquirable on the worker, provisions a pinned
installation, launches from verified local bytes, answers health probes, and
shuts down cleanly. Its image is digest-pinned, its container runs on a
private network with the artifact mounted read-only and the port published on
loopback only, and its operator-facing knobs are a short stable allowlist of
flags with validated values.

The launch argv is a security boundary. The runtime owns device assignment,
ports, model paths, and the flags that change them; the allowlist exists so
config cannot point the engine at different weights, a different port, or a
device the placement did not assign. A command template dissolves all of that
at once. There is no partial version of this trade: either the runtime
constructs the argv or the config does.

This costs coverage. An engine SBproxy has no driver for cannot be launched by
the model host. We accept that cost because writing a driver is bounded,
well-understood work against an existing trait, and because the alternative
breaks the property the whole model-host security story rests on.

## The escape hatch that already exists

Not being able to launch an engine is not the same as not being able to govern
it. Any OpenAI-compatible server you run yourself can sit behind the gateway
as a provider today:

```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: trtllm
          provider_type: openai
          base_url: http://10.0.0.7:8000/v1
          allow_private_base_url: true
          models:
            - my-model
```

You launch TensorRT-LLM, Kokoro, or your in-house container however you launch
things; SBproxy routes to it and applies guardrails, budgets, keys, and the
spend ledger, without ever holding launch authority over it. The division of
labor is explicit instead of hidden inside a command template.
[use-case-guardrails-everywhere.md](use-case-guardrails-everywhere.md) walks
through a worked example with a local Ollama.

What you give up against a managed deployment: artifact verification, fit
planning, admission, keep-alive, crash-loop handling, and the lifecycle CLI.
The gateway treats your engine as an upstream, because that is what it is.

## When to revisit

Two triggers reopen this decision.

**Repeated concrete demand for one engine.** If the same engine keeps coming
up with real deployments behind it, the answer is a typed driver for that
engine. That grows coverage where demand is proven and keeps the seam intact.

**A signed engine-descriptor design.** There may eventually be a middle path:
third-party engines described by a manifest SBproxy verifies rather than code
it must ship. Any such design has a minimum bar before it is worth
considering:

- the descriptor is signed and the signature is verified before use;
- the image is digest-pinned in the descriptor, never a tag;
- the descriptor declares a capability set (formats, accelerators, readiness
  probe), not behavior;
- no free-form argv anywhere; any flag the descriptor exposes is declared
  with a type and validated the way allowlist flags are today;
- the runtime keeps owning devices, ports, mounts, and networking.

Nothing here commits to building that. The bar exists so a future proposal
can be measured against it instead of relitigating the boundary.

## Related

- [model-host.md](model-host.md) covers the managed engines that exist today.
- [security-model-host.md](security-model-host.md) explains the invariants a
  driver must uphold.
- [serving-engine-benchmark.md](serving-engine-benchmark.md) compares the two
  CUDA engines head to head.

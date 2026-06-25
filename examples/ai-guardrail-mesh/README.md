# AI guardrail mesh

Run the input guardrails as a cascade, collect the full verdict set, and
fuse it under a configurable rule, instead of blocking on the first
detector that flags.

See [`docs/ai-guardrail-mesh.md`](../../docs/ai-guardrail-mesh.md) for the
full reference.

## What this config does

- `block_threshold: 2`: a prompt is blocked only when at least two
  detectors agree, so a single noisy detector does not hard-block.
- `redact_on_flag: true`: a prompt that trips one detector (below the
  threshold) is masked by the PII redactor and forwarded.
- `cache: true`: a repeated prompt reuses the cached verdict.
- `latency_budget_ms: 50`: expensive classifiers are skipped once the
  budget is spent; the cheap detectors run first.

The label set also feeds the AI policy plane
([`examples/ai-policy-cel`](../ai-policy-cel/)) via `ai.guardrails.*`.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-guardrail-mesh/sb.yml
```

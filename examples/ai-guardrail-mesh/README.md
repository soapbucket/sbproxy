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

## Try it

```bash
# Clean prompt: 0 detectors flag, forwarded unchanged.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is the capital of France?"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 200 (with a valid OPENAI_API_KEY)

# One detector flags (pii: email) - below block_threshold: redacted and
# forwarded, not blocked.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact me at test@example.com please"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 200 (with a valid OPENAI_API_KEY)

# Two detectors flag (pii: email + regex_guard: forbidden-term) - quorum of
# 2 reached, blocked before dispatch. No API key needed to see this one.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact me at test@example.com about forbidden-term issue"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 400 {"error":{"code":"pii,regex","message":"PII detected: email; Content blocked: matched regex pattern \"forbidden-term\"","type":"guardrail_violation"}}
```

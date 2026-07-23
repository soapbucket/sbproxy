# Guardrail mesh
*Last modified: 2026-07-22*

The serial guardrail chain blocks on the first security detector that flags.
The guardrail mesh instead runs the input detectors as a cascade, collects
security verdicts and routing labels, and fuses the security verdicts under a
configurable rule.
That unlocks three behaviors the serial chain cannot express: a quorum
block, redact-and-continue, and a latency-budgeted cascade with a verdict
cache.

Default off: with no `mesh` block under `guardrails`, the pipeline keeps
the serial block-on-any behavior.

## Configuration

```yaml
guardrails:
  input:
    - type: injection
    - type: pii
      patterns: [email]
    - type: regex_guard
      action: block
      config:
        deny: [forbidden-term]
  mesh:
    block_threshold: 2     # block only when >= 2 detectors flag (1 = block-on-any)
    redact_on_flag: true   # below the threshold, mask the prompt and continue
    cache: true            # reuse a verdict for a repeated prompt
    cache_capacity: 1024   # verdict cache size
    latency_budget_ms: 50  # stop launching expensive detectors past the budget
```

## Fusion

The mesh runs every input detector (cheap regex / PII / schema first, then
the more expensive classifiers) and counts security verdicts. A
`type: classifier` prompt-routing label is still published to the policy
plane, but it is non-enforcing and does not contribute to the count.

- `block_threshold` is the quorum: the request is blocked when
  security `flagged_count >= block_threshold`. `1` reproduces the serial
  security behavior; `0` never blocks on the count.
- `redact_on_flag`: when a security guardrail flags but the count is below
  the block threshold, the prompt is masked by the origin's PII redactor
  and the request continues, instead of passing through untouched. Routing
  labels do not trigger redaction.

The full label set is published to the AI policy plane's
[`ai.guardrails.*`](ai-policy-cel.md) namespace, so a CEL rule can fuse the
verdicts further (for example, route a multi-flag prompt to a cheaper model
and emit an audit event).

## Latency cascade and cache

Detectors run cheap-first. With `latency_budget_ms` set, once the budget is
spent the remaining (expensive) detectors are skipped, so the mesh degrades
gracefully under load rather than paying every classifier on every request.

With `cache` enabled, a verdict is cached by a combined hash of the prompt
text, message roles/content structure, and role-aware classifier scope, so a
repeated or replayed prompt skips re-running the detectors without aliasing
two conversations that flatten to the same text. The cache lives on the
compiled pipeline, so two origins with different guardrails never share an
entry.

## Try it

The runnable example is in
[`examples/ai-guardrail-mesh/`](../examples/ai-guardrail-mesh/).

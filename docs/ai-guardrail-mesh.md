# Guardrail mesh
*Last modified: 2026-08-01*

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

Every key under `mesh` is optional, and the block as a whole is optional.
Omitting it keeps the serial chain.

| Key | Default | What changes if you set it |
|---|---|---|
| `block_threshold` | `1` | How many security detectors must flag before the request is rejected. `1` is the serial block-on-any behavior. `2` needs a quorum, so one noisy detector cannot hard-block on its own. `0` never blocks on the count, which leaves the mesh as a pure labelling pass for the policy plane. |
| `redact_on_flag` | `false` | When a detector flags but the count is under the threshold, `true` masks the prompt with the origin's PII redactor and forwards it. `false` forwards the prompt untouched. |
| `latency_budget_ms` | unset | Wall-clock budget for optional detectors. Once it is spent the cascade stops launching them. Unset runs every detector. Enforcing safety classifiers run regardless of the budget. |
| `cache` | `false` | `true` caches each verdict so a repeated prompt skips the detectors. |
| `cache_capacity` | `1024` | Entries held in that verdict cache. Only read when `cache: true`. |

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

## Calling it

The runnable configuration is
[`examples/ai-guardrail-mesh/`](../examples/ai-guardrail-mesh/), and it is the
config block above. Start it:

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-guardrail-mesh/sb.yml
```

Nothing about the client changes. Send an ordinary chat request:

```bash
curl -sS -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact me at test@example.com about forbidden-term issue"}]}'
```

That prompt trips two detectors. `pii` matches the address against its
`email` pattern, and `regex_guard` matches `forbidden-term` against its deny
list. Two is the configured quorum, so the mesh blocks and the provider is
never called:

```json
{
  "error": {
    "code": "pii,regex",
    "message": "PII detected: email; Content blocked: matched regex pattern \"forbidden-term\"",
    "request_id": "<differs on every request>",
    "type": "guardrail_violation"
  }
}
```

Error-envelope keys are serialised in alphabetical order, not in the order
they are described here.

The status is `400`. Three things in that body are worth reading. `code` is
the comma-joined list of the security detectors that flagged, in the order
the cascade ran them, which is cheap-first rather than config order. `message`
joins their reasons with `; ` in that same order, so the two fields line up
position by position. `request_id` is the correlation handle for the access
log, and it is the only field here that changes between runs.

Because the block happens before dispatch, this request needs no working
provider key. The two requests below do reach the provider, so they return a
model response only when `OPENAI_API_KEY` is a real key:

```bash
# One detector flags. Below the quorum, so the prompt is masked and forwarded.
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact me at test@example.com please"}]}'

# No detector flags. Forwarded unchanged.
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is the capital of France?"}]}'
```

Both return the provider's own chat completion, so the body depends on the
model rather than on SBproxy. The difference between them is not visible in
the response: it is that the first one reached the provider with the address
masked.

To see the quorum actually doing something, drop `block_threshold` to `1` and
re-send the email-only prompt. One detector is now enough, so the prompt that
was masked and forwarded is rejected instead:

```json
{
  "error": {
    "code": "pii",
    "message": "PII detected: email",
    "request_id": "<differs on every request>",
    "type": "guardrail_violation"
  }
}
```

That is the difference `block_threshold: 2` buys: with the quorum in place the
same prompt reaches the model, with the address masked, rather than failing.

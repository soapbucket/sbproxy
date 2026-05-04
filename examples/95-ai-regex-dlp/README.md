# Custom regex DLP guardrail on AI traffic

*Last modified: 2026-04-27*

Built-in PII detection covers the obvious patterns (email, phone, SSN, credit card). Real organisations have their own confidential vocabulary: project codenames, internal doc IDs, source-control URLs, support ticket numbers. A regex guardrail extends the input pipeline with arbitrary patterns so confidential data never leaves the building, even if a developer accidentally pastes it into an AI request. Three layers run on every prompt: built-in PII detection (block on hit), a `regex` guardrail (`action: block`) with operator-supplied patterns blocking project codenames and internal references, and a second `regex` guardrail (`action: allow`) that acts as a positive filter requiring at least one approved engineering keyword. All three run before the upstream provider is contacted; a hit returns a 4xx with `sbproxy_ai_guardrail_blocks_total` incremented under the matching category.

## Run

```bash
export OPENAI_API_KEY=sk-...
sb run -c sb.yml
```

## Try it

```bash
# Clean prompt that mentions an approved keyword (release notes) - 200.
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[
      {"role":"user","content":"Summarise the public release notes."}
  ]}' | jq .choices[0].message
```

```bash
# Codename leak - blocked by the operator regex layer.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[
      {"role":"user","content":"Help me debug Project Bluebird."}
  ]}'
```

```bash
# Off-topic prompt - no approved keyword, blocked by the allow filter.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[
      {"role":"user","content":"Tell me a joke about cats."}
  ]}'
```

```bash
# Built-in PII layer catches a leaked email address even when no
# operator pattern matches.
curl -i http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[
      {"role":"user","content":"Mail me at alice@example.com please."}
  ]}'
```

## What this exercises

- `guardrails.input` running in order before the AI provider is contacted
- `type: pii` with `patterns: [email, phone, ssn, credit_card]` and `action: block`
- `type: regex` with operator-supplied patterns and `action: block`
- `type: regex` with `action: allow` as a positive scope filter (the prompt must match at least one allow pattern)

## See also

- [docs/ai-gateway.md](../../docs/ai-gateway.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)

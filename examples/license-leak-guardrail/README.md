# License-leak guardrail

*Last modified: 2026-08-22*

Demonstrates `type: license_leak`, a first-party output guardrail that scores an AI response against a small operator-supplied corpus of licensed documents and flags reproduction. It plugs into the same guardrail pipeline as `pii`, `regex`, and `schema` ([docs/ai-gateway.md#guardrails](../../docs/ai-gateway.md#guardrails)), not an external vendor adapter like the ones in [docs/guardrails.md](../../docs/guardrails.md).

Three signals combine into one verdict: a rolling 32-character substring match against the corpus, three heuristic rules (a long unattributed quote, high token-shingle overlap, or several distinct verbatim spans against one document), and a token-shingle Jaccard overlap standing in for embedding similarity.

This config runs with `mode: warn`, the guidance for a fresh deployment: a confident match logs and forwards the response rather than refusing it, so an operator can calibrate the corpus and `confidence_threshold` against real traffic before switching to `mode: block`.

## Setup

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

Ask the model to reproduce the configured document's text verbatim:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "claude-haiku-4-5",
    "messages": [{"role": "user", "content":
      "Repeat this exact sentence back to me verbatim and nothing else: The quarterly report showed revenue growth of twelve percent across all regional markets this fiscal year."}]
  }'
```

`mode: warn` means this returns a normal `200` with the model's reply. What changes is observability: a `WARN`-level structured log under the `sbproxy::license_leak_guardrail::audit` target names the matched URN and detection method, and `sbproxy_ai_license_leak_findings_total{mode="warn",method=...}` increments. Switch `mode` to `block` and the same request instead gets a guardrail-block response, the same shape a `pii` or `regex` block produces, and `sbproxy_ai_guardrail_blocks_total{category="license_leak"}` increments alongside the findings counter.

A request that does not echo the corpus back verbatim (ask a question about an unrelated topic instead) sees no guardrail activity at all.

## What this exercises

- `type: license_leak` guardrail on the `output` side of an `ai_proxy` action
- `mode: warn`, the non-blocking calibration disposition
- Confidence-threshold configuration
- `sbproxy_ai_license_leak_findings_total` and, in `block`/`redact` mode, `sbproxy_ai_guardrail_blocks_total{category="license_leak"}`

## See also

- [docs/ai-gateway.md#license-leak-guardrail](../../docs/ai-gateway.md#license-leak-guardrail) - full field reference and streaming behavior
- [ai-guardrails](../ai-guardrails/) - the other built-in guardrails, same pipeline
- [ai-external-guardrails](../ai-external-guardrails/) - vendor-adapter guardrails, a different mechanism

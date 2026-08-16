# Classifier-backed prompt routing

*Last modified: 2026-08-16*

Classify prompts locally with an operator-supplied sentence-embedding model,
then route each predicted class through the existing AI policy plane. The
example sends documentation work to `gpt-4o-mini` while coding and
unclassified prompts keep the requested model.

## Run

Download `all-MiniLM-L6-v2` using the commands at the top of
[`sb.yml`](sb.yml), then run:

```bash
export OPENAI_API_KEY=sk-...
sbproxy examples/ai-classifier-routing/sb.yml
```

The released binary includes the `inprocess-classify` feature. A source build
that disables default features must opt in to that feature.

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4.1","messages":[{"role":"user","content":"Write an upgrade guide for this release."}]}' \
  | jq -r .model
```

The response `model` field starts with `gpt-4o-mini` when the classifier
emits `documentation` (OpenAI returns the resolved dated snapshot, e.g.
`gpt-4o-mini-2024-07-18`, not the bare alias). A coding or unclassified
prompt keeps the originally requested model instead, e.g. `gpt-4.1` comes
back as `gpt-4.1-2025-04-14`. Classifier output is a non-enforcing routing label in both
the serial and mesh guardrail paths. The class appears in
`ai.guardrails.labels` for the CEL policy to consume and never contributes to
a security block quorum.

The model and tokenizer are loaded when the origin's guardrail pipeline is
first used. If either artifact cannot be loaded, the classifier logs a
warning and emits no labels, so the request keeps its original routing.

## See also

- [AI gateway guardrails](../../docs/ai-gateway.md#embedding-classifier)
- [Local inference](../../docs/local-inference.md)
- [AI policy plane](../../docs/ai-policy-cel.md)

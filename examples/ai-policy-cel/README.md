# AI policy plane (CEL)

One sandboxed CEL expression that fuses guardrail verdicts, budget state,
the routing candidate, and principal context into a closed set of typed
actions: `block`, `redact`, `route_to:<model>`, `set_sink_tag:<tag>`,
`audit:<priority>`, or `allow`.

See [`docs/ai-policy-cel.md`](../../docs/ai-policy-cel.md) for the full
reference and the `ai.*` namespace.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-policy-cel/sb.yml
```

This policy routes free-tier requests that ask for the expensive model down
to the cheap one and tags the spend record:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -H 'SB-Attr-Risk-Tier: free' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}' \
  | jq -r '.model'
```

The response `model` comes back as `gpt-4o-mini`: the policy rerouted it. A
request without the free tier header is served as `gpt-4o` unchanged.

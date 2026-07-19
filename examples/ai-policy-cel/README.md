# AI policy plane (CEL)

*Last modified: 2026-07-19*

One sandboxed CEL expression that fuses guardrail verdicts, budget state,
the routing candidate, and principal context into a closed set of typed
actions: `block`, `redact`, `route_to:<model>`, `compression:<selector>`,
`set_sink_tag:<tag>`, `audit:<priority>`, or `allow`.

See [`docs/ai-policy-cel.md`](../../docs/ai-policy-cel.md) for the full
reference and the `ai.*` namespace.

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-policy-cel/sb.yml
```

This policy routes free-tier requests that ask for the expensive model down
to the cheap one, selects the named stateless `compact` compression profile,
and tags the spend record:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -H 'SB-Attr-Risk-Tier: free' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}' \
  | jq -r '.model'
```

The response `model` comes back as `gpt-4o-mini`: the policy rerouted it. A
request without the free tier header is served as `gpt-4o` unchanged.

The CEL expression sees `ai.tokens.input_est` before compression. Known OpenAI
models use a registered tokenizer; unknown models use the UTF-8 byte-length
fallback. The selected `compact` profile has an explicit 512-token input
budget, so a long free-tier request is trimmed without Redis or worker-local
conversation state:

```bash
LONG_CONTEXT="$(awk 'BEGIN { for (i = 0; i < 300; i++) printf "historical item %d with repeated detail. ", i }')"
jq -n --arg context "$LONG_CONTEXT" '{
  model: "gpt-4o",
  messages: [
    {role: "system", content: "Preserve the newest instruction."},
    {role: "user", content: $context},
    {role: "user", content: "Return the newest instruction in five words."}
  ]
}' > /tmp/sbproxy-cel-compression.json

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H 'SB-Attr-Risk-Tier: free' \
  --data-binary @/tmp/sbproxy-cel-compression.json \
  | jq -r '.model'
```

`X-Compression` has higher precedence than CEL. This request still follows the
free-tier model route, but preserves the complete caller context:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -H 'SB-Attr-Risk-Tier: free' \
  -H 'X-Compression: off' \
  --data-binary @/tmp/sbproxy-cel-compression.json \
  | jq -r '.model'
```

SBproxy strips `X-Compression` before upstream dispatch. A malformed or
undeclared header returns `400`. A malformed or undeclared CEL compression
selector safely resolves to `off` and emits
an `ai_compression_selection` event plus
`sbproxy_ai_compression_selection_total{source="cel_policy",outcome="invalid_operator"}`
instead of falling back to the route default.

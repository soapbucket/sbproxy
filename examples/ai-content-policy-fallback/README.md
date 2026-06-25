# Content-policy fallback

When a provider refuses a request on content-policy / safety grounds with a
4xx, route the refusal to the next (more permissive) provider in order
instead of returning it.

See [`docs/ai-llm-aware-resilience.md`](../../docs/ai-llm-aware-resilience.md)
for the full reference.

## What this config does

Providers are tried in priority order (`fallback_chain`): the stricter model
(`strict`) first, the more permissive one (`permissive`) as the
content-policy fallback. With `content_policy_fallback: true`, a refusal from
`strict` is routed to `permissive` rather than returned to the client.

Only a body that marks a content-policy / safety block triggers the
failover. A plain 4xx client error (a malformed request, an auth failure) is
returned unchanged, and a refusal embedded in a 200 response is a valid
completion and is not intercepted.

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/ai-content-policy-fallback/sb.yml
```

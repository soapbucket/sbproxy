# Parallel inspect-only moderation

*Last modified: 2026-08-28*

An `ai_guardrail_input` hook with `execution.mode: parallel` starts at
the same time as the upstream call, the way LiteLLM's
`async_moderation_hook` does. Allow adds no extra time-to-first-token.
Reject cancels the in-flight generation; the provider may still bill
that call. `sbproxy_ai_parallel_moderation_total` and
`sbproxy_ai_provider_attempts_total{outcome="moderation_cancelled"}`
are how you see that trade.

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-parallel-moderation/sb.yml
```

A prompt that does not contain `exfiltrate` is released. One that does
returns HTTP 422 with code `parallel_moderation`.

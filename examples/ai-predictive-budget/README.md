# Predictive budget (soft-landing)

Degrade gracefully as a budget scope approaches its cap instead of hitting
a hard cliff at 100%: warn, then downgrade to a cheaper model, then block.

See [`docs/ai-predictive-budget.md`](../../docs/ai-predictive-budget.md) for
the full reference.

## What this config does

A `$10/day` workspace cap with soft-landing:

- `warn_at: 0.8`: past 80% spent, requests log a warning and continue.
- `downgrade_at: 0.95`: past 95%, requests are rewritten to `gpt-4o-mini`
  before the hard block, and the downgrade is tagged on the usage record.
- the hard `on_exceed: block` still fires at 100%.

The live fraction is also exposed to the AI policy plane as
`ai.budget.fraction` (see [`examples/ai-policy-cel`](../ai-policy-cel/)).

## Run

```bash
export OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-predictive-budget/sb.yml
```

## Try it

```bash
# Ordinary chat request against the $10/day workspace cap.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Say hi in one word."}]}' \
  http://127.0.0.1:8080/v1/chat/completions
# 200 (with a valid OPENAI_API_KEY)

# Malformed body: rejected before any budget check runs.
curl -s -H 'Host: ai.local' -H 'Content-Type: application/json' \
  -d 'not json' \
  http://127.0.0.1:8080/v1/chat/completions
# 400 {"error":"invalid JSON body"} - no API key needed to see this one
```

Reaching `warn_at` / `downgrade_at` / the hard cap takes real accumulated
spend, so send enough real requests to cross 80% of the $10 cap and watch
the response's `model` field switch to `gpt-4o-mini` past 95%, and the
usage record gain a `budget_soft_landing` tag.

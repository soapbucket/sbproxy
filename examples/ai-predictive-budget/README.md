# Predictive budget: warn, then downgrade, then block

The runnable half of [docs/ai-predictive-budget.md](../../docs/ai-predictive-budget.md). A fixed-window budget is a cliff: requests pass until the cap, then stop. Soft landing degrades on the way up instead, so spend tapers rather than ending.

| Band | Preflight fraction | What happens to the request |
|---|---|---|
| below `warn_at` | under 0.8 | Nothing changes. |
| `warn_at` to `downgrade_at` | 0.8 to 0.95 | Allowed, and a warning is logged. |
| `downgrade_at` to the cap | 0.95 to 1.0 | The model is rewritten to `downgrade_to` before dispatch, and the spend record is tagged `budget_soft_landing`. |
| at or above the cap | 1.0 and up | The hard `on_exceed` action owns the decision. Here that is `block`, a 402. |

The threshold is compared against the fraction *before* the request is dispatched, which is why the walkthrough below reads the gauge before each call rather than after.

## The fixture, and why it exists

Every threshold is a function of accumulated spend, and spend comes from each completed call's own `usage` object. Waiting for real traffic to walk a workspace to 80% of its cap is not a demo, so `fixture.py` lets the request name the tokens it wants billed:

```json
{"model": "gpt-4o", "messages": [{"role": "user", "content": "spend=850"}]}
```

reports 850 prompt tokens and 0 completion tokens. Anything without a `spend=` marker reports 1. The number is a demo dial; nothing here tokenizes anything. The fixture also echoes the dispatched model back, which is what makes the downgrade visible from the client: the rewrite happens before dispatch, so the upstream is the only witness.

The budget tracker is in-memory and per process. It survives a reload on purpose and is cleared only by a restart, so each walk wants a fresh process.

## Run

```bash
python3 examples/ai-predictive-budget/fixture.py &
make run CONFIG=examples/ai-predictive-budget/sb.yml 2>&1 | tee /tmp/sbproxy-predictive-budget.log
```

The `tee` is only so the warn and downgrade log lines below can be grepped afterwards; nothing else needs it.

Or under compose, which is what the smoke runner uses:

```bash
cd examples/ai-predictive-budget
docker compose up -d --wait
```

Two of the commands below read files the proxy wrote, the log and the usage sink, so they want the local run rather than the compose one: under compose both files live inside the container.

## The whole ladder

Soft landing compares a threshold against a live fraction, so the walkthrough has to place that fraction rather than guess it. The script does that by measuring: one call of a known token count, read the gauge before and after, and every step after that is arithmetic. It assumes no price table and no conversion factor, so it lands in the right band even if either changes.

```bash
bash examples/ai-predictive-budget/bin/soft-landing.sh
```

<!-- CAPTURE: bash examples/ai-predictive-budget/bin/soft-landing.sh -->

Row 3 is the whole feature: the client asked for `gpt-4o` and the upstream was handed `gpt-4o-mini`, with no header, no error, and no change to the response shape.

## Where each band shows itself

Nothing is stamped on the response. There is no `X-SBproxy-*` header for a warn or a downgrade, so there are four places to look: the gauge, the log, the usage sink, and the 402.

The gauge is the fraction the thresholds are compared against, and it is served unauthenticated on the data-plane port:

```bash
curl -s http://127.0.0.1:8080/metrics | grep sbproxy_ai_budget_utilization_ratio
```

<!-- CAPTURE: curl -s http://127.0.0.1:8080/metrics | grep sbproxy_ai_budget_utilization_ratio -->

Both soft-landing bands log at warn level, and the downgrade line names the model it rewrote to:

```bash
grep -F 'soft-landing' /tmp/sbproxy-predictive-budget.log
```

<!-- CAPTURE: grep -F 'soft-landing' /tmp/sbproxy-predictive-budget.log -->

The `budget_soft_landing` tag is on the usage record and nowhere else: not on the response, not in metrics, not in the access log. A sink is the only way to query which requests were degraded:

```bash
python3 -c 'import json; [print(json.dumps({k: json.loads(l).get(k) for k in ("model","tag","cost_usd")})) for l in open("/tmp/sbproxy-predictive-budget-usage.jsonl") if json.loads(l).get("tag")]'
```

<!-- CAPTURE: python3 -c 'import json; [print(json.dumps({k: json.loads(l).get(k) for k in ("model","tag","cost_usd")})) for l in open("/tmp/sbproxy-predictive-budget-usage.jsonl") if json.loads(l).get("tag")]' -->

And the cap itself, once the window is spent:

```bash
curl -s -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=1"}]}'
```

<!-- CAPTURE: curl -s -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' -H 'Content-Type: application/json' -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=1"}]}' -->

Run the checked smoke cases from the repository root with:

```bash
bash scripts/examples-smoke.sh examples/ai-predictive-budget
```

Those three cases prove the cap without arithmetic: one tiny call, one call that bills past any configured rate, and the 402 that follows. The two soft-landing bands need a spend computed from the live gauge, which is what the script above is for.

## What this does not give you

- **A cluster-wide budget.** The tracker is a process-local map. Two gateway processes each enforce their own copy of the same cap unless a shared spend store is configured.
- **A refund.** The downgrade applies to the request being dispatched, not to spend already recorded.
- **Soft landing on every surface.** The bands run on the chat and completions dispatch path. Non-chat surfaces and realtime run the hard preflight only, so they block at the cap with no warn and no downgrade.

## Clean up

```bash
docker compose down -v
rm -f /tmp/sbproxy-predictive-budget-usage.jsonl /tmp/sbproxy-predictive-budget.log
```

## Read more

- [docs/ai-predictive-budget.md](../../docs/ai-predictive-budget.md) - the bands, the tightest-window rule, and the policy-plane integration
- [docs/ai-gateway.md](../../docs/ai-gateway.md) - the budget block in the wider AI gateway reference
- [examples/ai-policy-cel/](../ai-policy-cel/) - `ai.budget.fraction` composed with guardrail verdicts and principal context
- [examples/ai-usage-ledger/](../ai-usage-ledger/) - the tamper-evident sink the same tag lands in

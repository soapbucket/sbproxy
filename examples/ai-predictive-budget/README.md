# Predictive budget: warn, then downgrade, then block

![Predictive budget: warn, then downgrade, then block](../../docs/assets/ai-predictive-budget.gif)

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

```
1 below warn_at          preflight=0        status=200  served=gpt-4o
2 past warn_at           preflight=0.85     status=200  served=gpt-4o
3 past downgrade_at      preflight=0.969    status=200  served=gpt-4o-mini
4 at the cap             preflight=6000.969059999999 status=402  served=budget_exceeded
```

Row 3 is the whole feature: the client asked for `gpt-4o` and the upstream was handed `gpt-4o-mini`, with no header, no error, and no change to the response shape.

## Where each band shows itself

Nothing is stamped on the response. There is no `X-SBproxy-*` header for a warn or a downgrade, so there are four places to look: the gauge, the log, the usage sink, and the 402.

The gauge is the fraction the thresholds are compared against, and it is served unauthenticated on the data-plane port:

```bash
curl -s http://127.0.0.1:8080/metrics | grep sbproxy_ai_budget_utilization_ratio
```

```
# HELP sbproxy_ai_budget_utilization_ratio Budget utilization as ratio 0-1
# TYPE sbproxy_ai_budget_utilization_ratio gauge
sbproxy_ai_budget_utilization_ratio{scope="workspace"} 6000.969059999999
```

Both soft-landing bands log at warn level, and the downgrade line names the model it rewrote to:

```bash
grep -F 'soft-landing' /tmp/sbproxy-predictive-budget.log
```

```
2026-08-02T20:38:51.639345Z  WARN sbproxy_core::server::ai_dispatch: AI budget: approaching limit (soft-landing warn) fraction=0.85
2026-08-02T20:38:51.704920Z  WARN sbproxy_core::server::ai_dispatch: AI budget: approaching limit (soft-landing warn) fraction=0.851
2026-08-02T20:38:51.753606Z  WARN sbproxy_core::server::ai_dispatch: AI budget: soft-landing downgrade before hard cap fraction=0.969 new_model=gpt-4o-mini
2026-08-02T20:38:51.792899Z  WARN sbproxy_core::server::ai_dispatch: AI budget: soft-landing downgrade before hard cap fraction=0.9690599999999999 new_model=gpt-4o-mini
```

The `budget_soft_landing` tag is on the usage record and nowhere else: not on the response, not in metrics, not in the access log. A sink is the only way to query which requests were degraded. Only the downgrade band is tagged, because only a downgraded request was changed; a warn-band request is dispatched as sent and shows up in the log above and nowhere here:

```bash
python3 -c 'import json; [print(json.dumps({k: json.loads(l).get(k) for k in ("model","tag","cost_usd")})) for l in open("/tmp/sbproxy-predictive-budget-usage.jsonl") if json.loads(l).get("tag")]'
```

```
{"model": "gpt-4o-mini", "tag": "budget_soft_landing", "cost_usd": 0.06}
{"model": "gpt-4o-mini", "tag": "budget_soft_landing", "cost_usd": 6000000.0}
```

And the cap itself, once the window is spent:

```bash
curl -s -i http://127.0.0.1:8080/v1/chat/completions -H 'Host: ai.local' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"spend=1"}]}'
```

```
HTTP/1.1 402 Payment Required
content-type: application/json
content-length: 117
Date: Sun, 02 Aug 2026 20:38:51 GMT
Connection: keep-alive

{"error":{"message":"cost limit exceeded: $6000969.0600 >= $1000.0000","scope":"workspace","type":"budget_exceeded"}}
```

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

# AI gateway: per-request price ceiling

*Last modified: 2026-08-20*

A hard price ceiling evaluated per request, before any provider is selected. `max_price_per_request: 0.0001` sits below the cheapest estimate either configured candidate can produce, so as shipped every chat request is refused with 402 rather than dispatched over the ceiling. Both providers declare the logical model `chat-default` and rename it through their own `model_map` (`gpt-4o-mini` on OpenAI, `claude-sonnet-4-5` on Anthropic), so the refusal prices each candidate against the model it would actually have dispatched. The estimate reuses the same price resolution cost tracking bills with; there is no second price table. Full semantics are in the per-request price ceiling section of [docs/ai-gateway.md](../../docs/ai-gateway.md).

## Run

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
make run CONFIG=examples/price-ceiling/sb.yml
```

Neither key is dialed until a request clears the ceiling. The as-shipped refusal never reaches an upstream, so you can run this example with placeholder keys and still see it work.

## Refused, with the prices behind the refusal

The estimate is the short prompt plus the declared 1,000-token output cap, priced at each candidate's per-million rates:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "chat-default",
      "max_tokens": 1000,
      "messages": [{"role": "user", "content": "Draft a two-line status update."}]
    }' | jq .
{
  "error": {
    "ceiling_usd": 0.0001,
    "excluded": [
      {
        "estimated_cost_usd": 0.0006021,
        "model": "gpt-4o-mini",
        "price_source": "catalog",
        "provider": "openai"
      },
      {
        "estimated_cost_usd": 0.015042,
        "model": "claude-sonnet-4-5",
        "price_source": "catalog",
        "provider": "anthropic"
      }
    ],
    "message": "no eligible provider can serve this request under the price ceiling of $0.0001 per request; each candidate's estimated cost is listed in error.excluded",
    "request_id": "01a0213f19dd7810aff68cd184626bb3",
    "type": "price_ceiling_exceeded"
  }
}
```

`price_source: catalog` says both prices came from the built-in catalog. An operator `model_prices` entry would read `config`, a rate card `rate_card`, and a model nothing prices at all `fallback`, at the pessimistic $5 / $5 per million that will usually exclude it.

## Drop the output cap and the estimate goes up

With no `max_tokens`, `max_completion_tokens`, or `max_output_tokens` in the body, the ceiling assumes a 1,024-token completion so an output-priced model cannot slip under on a short prompt alone. Same request without the cap:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{
      "model": "chat-default",
      "messages": [{"role": "user", "content": "Draft a two-line status update."}]
    }' | jq -c '.error.excluded[]'
{"estimated_cost_usd":0.0006165,"model":"gpt-4o-mini","price_source":"catalog","provider":"openai"}
{"estimated_cost_usd":0.015402,"model":"claude-sonnet-4-5","price_source":"catalog","provider":"anthropic"}
```

## Raise the ceiling and watch it narrow instead of refuse

Set `max_price_per_request: 0.001` and reload. The OpenAI candidate at roughly $0.0006 now fits, the Anthropic candidate at roughly $0.0150 still does not, and routing proceeds over the survivor. Run with `RUST_LOG=sbproxy_core::server::ai_dispatch=debug` to see each exclusion:

```
DEBUG sbproxy_core::server::ai_dispatch: price ceiling excluded a routing candidate
  event="ai.price_ceiling.exclude" provider=anthropic model=claude-sonnet-4-5
  estimated_cost_usd=0.015042 price_source=catalog ceiling_usd=0.001
```

At `0.05` both candidates are eligible and routing behaves as if no ceiling were set. The request's admin row carries the verdict either way: `price_ceiling:allow` when everything fit, `price_ceiling:narrowed` when some candidates were dropped, and `price_ceiling:deny` with the excluded prices in the deny reason when the request was refused.

## A caller can tighten the ceiling, never raise it

The `x-sbproxy-max-price` request header takes a USD amount and is combined with the configured ceiling by taking the stricter of the two, so a request cannot talk the gateway out of the operator's guard:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -H 'x-sbproxy-max-price: 0.05' \
    -d '{"model":"chat-default","max_tokens":1000,"messages":[{"role":"user","content":"Draft a two-line status update."}]}'
402
```

A malformed or non-positive value is refused rather than ignored. A caller who asked for a bound and mistyped it must not dispatch unbounded:

```bash
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -H 'x-sbproxy-max-price: free-please' \
    -d '{"model":"chat-default","max_tokens":1000,"messages":[{"role":"user","content":"Draft a two-line status update."}]}' | jq .
{
  "error": {
    "message": "x-sbproxy-max-price is not a number: \"free-please\"",
    "request_id": "01a0213fa09b78229c146d7743a72995",
    "type": "invalid_price_ceiling"
  }
}
```

## Metrics

Each excluded candidate increments `sbproxy_ai_price_ceiling_total{outcome="candidate_excluded"}`, and each fully excluded request increments `sbproxy_ai_price_ceiling_total{outcome="refused"}`. A rising exclusion rate with a flat refusal rate means the ceiling is trimming the expensive tier; a rising refusal rate means it is blocking traffic outright.

## Ceiling vs. budget

The ceiling caps a single request's estimated price and keeps no state. Budgets (the `budget:` block) accumulate real usage per scope over a period. They compose: a request can pass a generous monthly budget and still be refused by the ceiling, or clear the ceiling and be blocked by an exhausted budget. See [examples/ai-budget/](../ai-budget/) for the budget side.

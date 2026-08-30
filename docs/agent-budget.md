# agent_budget policy
*Last modified: 2026-08-29*

![70 rapid requests from a Cursor user agent: 200s until the per-agent budget trips and the rest return 429](assets/agent-budget.gif)

The budget keys on the resolved agent_id, not the client IP ([config](../examples/agent-budget/)).

The `agent_budget` policy is a semantic rate-limit primitive keyed on the resolved `agent_id`. Standard per-IP / per-user / per-key limits assume humans pause between requests; agents driven by an LLM loop fire at network speed and trip those buckets immediately. Datadog reports roughly a third of LLM-span errors in production are rate-limit denials for exactly that reason.

This is a rate cap, not a cost cap: it tracks requests and tokens per minute/hour against one agent's identity, not dollars against a workspace. For a dollar-denominated spend cap with graceful degradation, see [ai-predictive-budget.md](ai-predictive-budget.md).

One bucket per named agent collapses "every request from the Cursor instance" or "every request from the same OpenAI Assistant" into a single budget that an operator can actually size. The `agent_id` comes from the built-in agent-class catalog in `sbproxy-classifiers`: a User-Agent regex match, not ADRF and not `agent_detect`. That catalog includes coding agents such as Cursor (`Cursor/0.42.0` and `cursor-agent/...` resolve to `anysphere-cursor`), so the walkthrough below keys a real named bucket. When no catalog entry matches, the resolver still stamps the `human` sentinel and that is a named bucket, not `on_anonymous`; `on_anonymous` applies only when `agent_id` is unset (the agent-class feature is off).

## Config

```yaml
origins:
  "ai.example.com":
    upstream: https://api.openai.com
    auth:
      type: bearer
    policies:
      - type: agent_budget
        # Token-bucket refill rate, per agent_id.
        requests_per_minute: 60
        # Rolling hourly LLM-token budget per agent_id. Charged from
        # the usage the provider reports on each completed response;
        # a request over the accumulated cap is refused up front, the
        # same way an exceeded requests_per_minute is.
        tokens_per_hour: 100000
        # Max simultaneous in-flight requests per agent_id. RAII guard
        # releases the slot when the request completes.
        burst: 10
        # What to do when the cap fires.
        # - deny (default): respond 429.
        # - log: emit the decision metric, pass the request through.
        # - downgrade: dispatcher routes to a cheaper model.
        on_exceed: deny
        # What to do when the request has no resolved agent_id.
        # - skip (default): no enforcement.
        # - shared: all anonymous requests share one bucket.
        on_anonymous: skip
```

## Decisions

The policy reports its verdict to the dispatcher; the dispatcher maps the verdict to a real action:

| Verdict | `on_exceed` | HTTP outcome |
|---|---|---|
| Within budget | n/a | pass through |
| Cap fired, deny | `deny` | 429, JSON body naming the cap that fired |
| Cap fired, log | `log` | pass through, metric increments |
| Cap fired, downgrade | `downgrade` | dispatcher picks the cheaper AI provider for this request |

## Calling it

The runnable configuration is
[`examples/agent-budget/`](../examples/agent-budget/): the block above with
`requests_per_minute: 60`, `burst: 10`, `on_exceed: deny`, and
`on_anonymous: skip`, in front of a plain proxy origin. Start it:

```bash
make run CONFIG=examples/agent-budget/sb.yml
```

The budget keys on the resolved `agent_id`, so what identifies the caller is
the `User-Agent`, not the address it comes from. Send requests fast enough to
outrun the refill:

```bash
for i in $(seq 1 70); do
  curl -s -o /dev/null -w '%{http_code} ' \
    -H 'Host: ai.local' \
    -H 'User-Agent: Cursor/0.42.0' \
    http://127.0.0.1:8080/anything
done
```

The bucket starts full at 60 and refills at one token per second, so the first
60 pass straight through and after that the loop is throttled to roughly the
refill rate. A run that takes about twenty seconds prints something close to:

```
200 200 200 ... 200 429 429
```

The exact request that first returns `429` depends on how fast the loop runs,
because tokens keep arriving while it does. That is the point of a token
bucket rather than a fixed window: there is no cliff at a request count, only
a sustained rate.

Ask for the failing response in full to see what a denial says:

```bash
curl -sS -i \
  -H 'Host: ai.local' \
  -H 'User-Agent: Cursor/0.42.0' \
  http://127.0.0.1:8080/anything
```

```http
HTTP/1.1 429 Too Many Requests
content-type: application/json
content-length: 54

{"error":"agent budget exceeded: requests per minute"}
```

The body names which of the three caps fired, so `requests_per_minute`,
`tokens_per_hour`, and `burst` are distinguishable from the client side
without reading the proxy log. The other two read
`agent budget exceeded: tokens per hour` and `agent budget exceeded: burst`.
There is no `Retry-After` header on this response; the refill rate is
`requests_per_minute / 60` per second and is not advertised per request.

Change only the `User-Agent` and the budget starts over, because that resolves
to a different `agent_id` and therefore a different bucket. Send the two
back to back, straight after the drain above, so the drained bucket has not had
a second to refill:

```bash
curl -s -o /dev/null -w 'cursor=%{http_code} ' \
  -H 'Host: ai.local' -H 'User-Agent: Cursor/0.42.0' \
  http://127.0.0.1:8080/anything
curl -s -o /dev/null -w 'claudebot=%{http_code}\n' \
  -H 'Host: ai.local' -H 'User-Agent: ClaudeBot/1.0' \
  http://127.0.0.1:8080/anything
# cursor=429 claudebot=200
```

Wait a second between those two and the first one returns `200` again, because
the bucket has refilled one token. The buckets are per agent, not per client
address: both requests came from the same machine.

A request with no recognized agent resolves no `agent_id` at all, and
`on_anonymous: skip` means the policy does not enforce against it. Set
`on_anonymous: shared` to collapse that traffic into one fallback bucket
instead.

## How the token budget is enforced

A response's token count is only known after the response completes, so
`tokens_per_hour` enforcement is two-phase:

1. **Check up front.** Every admission compares the agent's accumulated
   hourly counter against the cap, at the same point
   `requests_per_minute` is checked. A request over the cap gets the
   same treatment as an exceeded request budget: `429` under
   `on_exceed: deny`, with the body reading
   `agent budget exceeded: tokens per hour`, and the same
   pass-through-with-metric behavior under `log` and `downgrade`.
2. **Charge after the response.** When the AI gateway extracts the
   provider's reported usage from a completed response, the prompt and
   completion tokens are charged against the agent's counter. Streamed
   responses charge at end of stream, where the usage frame the
   provider sends in its final events is aggregated.

Two consequences of that shape are worth knowing:

* The request that crosses the cap is served, and so does every other
  request from the same agent already admitted and still in flight: none
  of them can be charged until their response completes, so a concurrent
  admission check cannot see it yet. The next check to run *after* a
  charge lands is the one that refuses. Under `burst: 1` that bounds the
  overshoot to one response; a higher `burst`, or none configured, lets
  that many concurrent responses land unaccounted for before the counter
  catches up.
* A response that reports no usage consumes zero. That covers upstream
  error responses, providers that omit the `usage` block, and surfaces
  that never report token counts at all (non-AI traffic through the
  same origin, for example). The budget never invents an estimate.

## The hourly window slides

The counter is a sliding window, not a fixed one. It keeps the current
hour's spend plus the previous hour's, and weights the previous by how
much of the current hour is left:

```text
estimate = previous * (1 - elapsed_in_hour / hour) + current
```

A fixed window would drop the whole count at the boundary, so an agent
that spent its full cap just before the reset could spend it again just
after and consume close to **twice** its hourly allowance across that
hour. Every individual window would have looked correctly enforced while
the bill disagreed. The longer the window, the worse that gets, which is
why it matters at an hour and not at a minute.

The weighting assumes the previous hour's spend was spread evenly across
it, so the estimate is an approximation. That is deliberate: an exact
answer needs a stored record of every charge in the window, and this
needs two integers. The error is bounded by the previous hour's count and
decays linearly to zero as the current hour advances, in both directions.
It never compounds across windows the way a boundary reset does.

`tokens_per_hour` is enforced per replica. A fleet of ten enforces ten
times the configured cap, the same as any other local counter here. That
is a known limit, tracked separately; what changed is that each replica
now enforces its own cap honestly instead of admitting double around
every boundary.

## Observability

* `sbproxy_policy_triggers_total{origin, policy_type="agent_budget", action="deny"}` increments on `deny` denials.
* `sbproxy_agent_budget_decisions_total{agent_id, outcome}` increments on every sub-budget trip, with `outcome` set to `deny`, `log`, or `downgrade` to match whichever `on_exceed` mode fired.
* Access log: `agent_id`, `agent_class`, `agent_vendor` carry the resolved agent identity. There is no per-policy verdict field on this stream; the verdict is the two metrics above.

## Why per-agent

A standard rate-limit policy keyed on IP or API key cannot distinguish "Cursor making 200 background completions while the user types" from "an attacker fanning out 200 distinct concurrent prompts". Both look identical to an IP-keyed bucket. Keying on `agent_id` (the resolved agent identity, not the network address) lets the operator size the legitimate background traffic without hardening to it, and lets the abuse path get blocked cleanly because the attacker cannot produce a fresh `agent_id` per request without re-resolving against the agent registry.

## Out of scope

* Cluster-shared budgets. Each proxy enforces its own local view of both the request and the token budgets; an attacker spreading across replicas sees N times the per-instance budget. A cluster-shared backend (Redis or shared KV) is the obvious follow-up; for now, treat the per-instance budget as the floor.
* Token estimates. Responses that report no usage consume zero, as described above; the budget does not fall back to a request-side estimate.

## See also

* [features.md](./features.md) - tour with policy examples.
* [examples/agent-budget/](../examples/agent-budget/) - runnable per-agent rate-limit fixture.
* [ai-gateway.md](./ai-gateway.md) - the AI surfaces the budget protects.
* [ai-predictive-budget.md](./ai-predictive-budget.md) - the dollar-denominated cost cap this rate cap complements.
* [configuration.md](./configuration.md) - the full schema.

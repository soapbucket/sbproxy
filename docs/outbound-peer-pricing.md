# Outbound peer-pricing pre-flight
*Last modified: 2026-07-09*

The `peer_pricing_preflight` policy is designed to read a peer's
published `llms.txt` before SBproxy issues an outbound request,
compare the advertised price against the operator's budget, and
either let the call through or short-circuit with a structured `402`
returned to the agent.

## Status

The configuration surface ships and parses today: the policy block
below validates, and the budget/decision logic exists as a typed,
unit-tested library API. Outbound enforcement is not yet wired. The
inbound policy chain's enforcer for this type allows every request
unconditionally, and no outbound dispatcher invokes the decision
logic, so configuring the policy has no runtime effect in the current
binary. The rest of this page describes the intended behaviour; read
it as design, not as what the proxy does today.

The policy is the outbound dual of
[`ai_crawl_control`](ai-crawl-control.md):

- `ai_crawl_control` advertises a price on inbound crawler requests.
- `peer_pricing_preflight` reads that price on outbound peer
  requests.

Both ends share the same vocabulary (content shapes, micros, tiered
routes) so the two halves of a cooperating-agent fetch agree on what
was charged.

## When to use this

Once the outbound wiring lands, the policy is meant for deployments
with agents inside the perimeter that call out to cooperating peers
that publish a priced manifest. Common shapes:

- An internal agent that fetches articles from a partner publisher.
- An MCP server that resolves tool URLs at peer hosts.
- A retrieval pipeline that pulls JSON blobs from a paid data peer.

The policy is silent for peers that do not publish a manifest. Set
`on_no_manifest: block` to require a manifest before allowing the
outbound call.

## How it is designed to work

None of the steps below run on the serving path today; they describe
the design the library API implements and the outbound dispatcher
will eventually call.

1. **Side-fetch the manifest.** The first outbound to a new peer
   would trigger `GET https://<peer>/llms.txt`. SBproxy parses the
   document with the priced-route parser in
   `sbproxy_modules::transform::llms_pricing`.
2. **Cache the parsed result.** Successfully parsed manifests cache
   for `cache_ttl` (default 1 hour). Peers that do not publish a
   manifest cache as a sentinel for 5 minutes so SBproxy does not
   re-probe on every outbound call.
3. **Match the outbound path.** The policy walks the manifest's
   `routes[]`, looking for a `route_pattern` that covers the
   outbound path. Trailing `*` is a suffix wildcard (`/articles/*`
   matches `/articles/intro`).
4. **Apply the budget.** When a route matches, the policy compares
   the route's `price_micros` against `max_price_per_request` and
   against the rolling 24-hour `daily_budget_micros`.
5. **Allow or block.**
   - Within budget: the outbound proceeds.
   - Over budget: the policy returns `402 Payment Required` to the
     original agent with a JSON body that names the peer, the route
     pattern, the price, the currency, and the shape so the agent
     can decide whether to top up, switch rails, or back off.

When more than one tier covers the path, the design picks the
cheapest tier whose `shape` is acceptable to the agent (parsed from
the agent's `Accept` header).

## Configuration

The policy block parses and validates today, attached to an origin
like any other policy.

```yaml
proxy:
  http_bind_port: 8080

origins:
  "peers.internal.example":
    action:
      type: proxy
      url: https://peer.example

    policies:
      - type: peer_pricing_preflight
        # Hard cap on a single outbound call, in major units of the
        # currency the peer advertises. Set to `null` (or omit) to
        # drop the per-request cap entirely.
        max_price_per_request: 0.01

        # Rolling 24-hour budget in micros (1e-6 of the currency).
        # Omit to drop the daily cap.
        daily_budget_micros: 10000000

        # How long to cache a successfully parsed manifest. Accepts
        # `1h`, `30m`, `5s`, etc. Defaults to 1h.
        cache_ttl: 1h

        # Behaviour when a peer either returns a non-200 or fails to
        # publish a parseable manifest. `allow` (the default) lets
        # the call through; `block` returns a 402 with
        # `reason: no_manifest`.
        on_no_manifest: allow
```

## 402 body

When the pre-flight blocks an outbound call, the decision logic
produces a JSON body for the original agent so the agent has enough
context to react.

```json
{
  "error": "peer_pricing_preflight",
  "reason": "over_per_request_budget",
  "peer_host": "peer.example",
  "route_pattern": "/data/*",
  "price_micros": 50000,
  "currency": "USD",
  "shape": "json",
  "max_price_per_request_micros": 10000
}
```

The `reason` field is one of:

- `over_per_request_budget` - the matched route's price exceeded
  `max_price_per_request`.
- `over_daily_budget` - authorising this call would have crossed the
  rolling 24-hour budget.
- `no_manifest` - the peer did not publish a parseable manifest and
  the policy was configured with `on_no_manifest: block`.

The body includes whichever budget knobs the operator configured so a
debugging agent can tell exactly which cap fired.

## Observability

Nothing is emitted today because nothing enforces. The design
reserves a `sbproxy.outbound.peer_pricing` event carrying the peer
host, matched route, authorised price, and content shape, but no
code emits it yet.

## Wire shape: the parser

The policy reads peer manifests with
`sbproxy_modules::transform::llms_pricing::parse`, which is the input
dual of `sbproxy_modules::projections::llms::render`:

```rust,ignore
let parsed = parse(bytes)?;
println!("sitename = {:?}", parsed.sitename);
for route in parsed.routes {
    println!(
        "{} agent={:?} shape={:?} price={} {}",
        route.route_pattern,
        route.agent_id,
        route.shape,
        route.price_micros,
        route.currency,
    );
}
```

`parse` is intentionally lenient: bullet lines that the parser cannot
decode are dropped without raising, and the only error path is
non-UTF-8 input.

## Example

A runnable example lives at
[`examples/outbound-peer-pricing/sb.yml`](../examples/outbound-peer-pricing/sb.yml).

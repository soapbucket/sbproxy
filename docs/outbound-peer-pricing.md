# Outbound peer-pricing pre-flight
*Last modified: 2026-05-14*

When SBproxy issues an outbound request to a cooperating peer, the
`peer_pricing_preflight` policy reads the peer's published
`llms.txt`, compares the advertised price against the operator's
budget, and either lets the call through or short-circuits with a
structured `402` returned to the agent.

The policy is the outbound dual of
[`ai_crawl_control`](ai-crawl-control.md):

- `ai_crawl_control` advertises a price on inbound crawler requests.
- `peer_pricing_preflight` reads that price on outbound peer
  requests.

Both ends share the same vocabulary (content shapes, micros, tiered
routes) so the two halves of a cooperating-agent fetch agree on what
was charged.

## When to use this

Turn the policy on whenever you have agents inside your perimeter
that call out to cooperating peers that publish a priced manifest.
Common shapes:

- An internal agent that fetches articles from a partner publisher.
- An MCP server that resolves tool URLs at peer hosts.
- A retrieval pipeline that pulls JSON blobs from a paid data peer.

The policy is silent for peers that do not publish a manifest. Set
`on_no_manifest: block` to require a manifest before allowing the
outbound call.

## How it works

1. **Side-fetch the manifest.** The first outbound to a new peer
   triggers `GET https://<peer>/llms.txt`. SBproxy parses the
   document with the priced-route parser in
   `sbproxy_modules::transform::llms_txt`.
2. **Cache the parsed result.** Successfully parsed manifests cache
   for `cache_ttl` (default 1 hour). Peers that do not publish a
   manifest cache as a sentinel for 5 minutes so SBproxy does not
   re-probe on every outbound call.
3. **Match the outbound path.** The policy walks the manifest's
   `routes[]`, looking for a `route_pattern` that covers the
   outbound path. Trailing `*` is a suffix wildcard (`/articles/*`
   matches `/articles/intro`).
4. **Apply the budget.** When a route matches, SBproxy compares the
   route's `price_micros` against `max_price_per_request` and
   against the rolling 24-hour `daily_budget_micros`.
5. **Allow or block.**
   - Within budget: the outbound proceeds and SBproxy emits a
     `sbproxy.outbound.peer_pricing` event with the matched route +
     authorised price.
   - Over budget: the policy returns `402 Payment Required` to the
     original agent with a JSON body that names the peer, the route
     pattern, the price, the currency, and the shape so the agent
     can decide whether to top up, switch rails, or back off.

When more than one tier covers the path, SBproxy picks the cheapest
tier whose `shape` is acceptable to the agent (parsed from the
agent's `Accept` header).

## Configuration

```yaml
policies:
  - type: peer_pricing_preflight
    # Hard cap on a single outbound call, in major units of the
    # currency the peer advertises. Set to `null` (or omit) to drop
    # the per-request cap entirely.
    max_price_per_request: 0.01

    # Rolling 24-hour budget in micros (1e-6 of the currency). Omit
    # to drop the daily cap.
    daily_budget_micros: 10000000

    # How long to cache a successfully parsed manifest. Accepts
    # `1h`, `30m`, `5s`, etc. Defaults to 1h.
    cache_ttl: 1h

    # Behaviour when a peer either returns a non-200 or fails to
    # publish a parseable manifest. `allow` (the default) lets the
    # call through; `block` returns a 402 with
    # `reason: no_manifest`.
    on_no_manifest: allow
```

## 402 body

When the pre-flight blocks an outbound call, SBproxy returns a JSON
body to the original agent so the agent has enough context to react.

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

Every authorised call emits a `sbproxy.outbound.peer_pricing` event
carrying:

- `peer_host` - the manifest publisher.
- `route_pattern` - the matched route.
- `price_micros` + `currency` - the price the operator just committed
  to.
- `shape` - the matched content shape.

Blocked calls emit the same event with an additional `blocked: true`
flag and the `reason` string from the 402 body.

## Wire shape: the parser

The policy reads peer manifests with
`sbproxy_modules::transform::llms_txt::parse`, which is the input
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

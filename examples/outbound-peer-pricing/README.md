# Outbound peer-pricing pre-flight

Demonstrates the `peer_pricing_preflight` policy: when an internal
agent calls a cooperating peer through this origin, SBproxy reads
the peer's published `llms.txt`, gates the call on the configured
budget, and returns a structured `402 Payment Required` to the agent
if the price overruns the cap.

See [`docs/outbound-peer-pricing.md`](../../docs/outbound-peer-pricing.md)
for the full contract and the 402 body schema.

## Run

```bash
make run CONFIG=examples/outbound-peer-pricing/sb.yml
```

## Try it

Pick a peer that publishes a priced `llms.txt` at
`https://<peer>/llms.txt`. The first outbound to that peer
side-fetches the manifest; subsequent outbounds within the
`cache_ttl` window reuse the cached parse.

If you want a stand-in peer for local testing, mirror the shape of
the manifest emitted by the
[`projections::llms::render`](../../crates/sbproxy-modules/src/projections/llms.rs)
projection.

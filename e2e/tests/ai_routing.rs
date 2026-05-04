//! End-to-end coverage for AI gateway routing strategies.
//!
//! `examples/17-ai-routing-fallback/sb.yml` documents
//! `fallback_chain`, `examples/18-ai-cost-optimized/sb.yml`
//! documents `cost_optimized`, and the `weighted` strategy is tested
//! at the unit level in `crates/sbproxy-ai/src/routing.rs`. Pinning
//! these end-to-end requires:
//!   1. A mock provider that can return both 200 (good) and 5xx
//!      (force failover) responses on demand. The OSS [`MockUpstream`]
//!      always returns 200 with a fixed JSON body, so it cannot
//!      drive the failover branch.
//!   2. An OpenAI-compatible JSON shape so the gateway's body
//!      translation layer accepts the upstream reply on the way back
//!      to the client.
//!
//! TODO: when a richer mock provider lands in the e2e harness, the
//! placeholders below should:
//!   * `weighted`: configure two providers with weights `1` and `3`,
//!     drive 100 requests, assert the heavier provider gets ~75% of
//!     traffic within tolerance.
//!   * `fallback_chain`: configure a primary that returns 503 and a
//!     secondary that returns 200; assert every client request lands
//!     on the secondary and the primary's failure count climbs.
//!   * `cost_optimized`: configure providers with weights `1`, `5`,
//!     `50` and assert (under light load) every request lands on the
//!     cheapest, lowest-weight provider.

#[test]
#[ignore = "needs configurable-status mock provider on sbproxy-e2e"]
fn weighted_routing_distributes_proportional_to_weights() {
    // Placeholder. See module docs for the missing harness piece.
}

#[test]
#[ignore = "needs configurable-status mock provider on sbproxy-e2e to drive 503 failover"]
fn fallback_chain_promotes_secondary_when_primary_fails() {
    // Placeholder. See module docs for the missing harness piece.
}

#[test]
#[ignore = "needs OpenAI-compatible mock response body to round-trip the gateway"]
fn cost_optimized_routes_to_cheapest_provider_under_light_load() {
    // Placeholder. See module docs for the missing harness piece.
}

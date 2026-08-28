# How SBproxy compares

*Last modified: 2026-08-28*

This page used to be a long competitor matrix. Those tables duplicated [architecture.md](architecture.md) and went stale the same way a features tour does. Use the walkthroughs and the capability rows below, which are the claims the test suite still binds to the code.

## Where to go instead

- What SBproxy *is*: [architecture.md](architecture.md), [api-gateway.md](api-gateway.md), [ai-gateway.md](ai-gateway.md), [mcp-and-agents.md](mcp-and-agents.md).
- Moving a LiteLLM proxy: [migration-litellm.md](migration-litellm.md).
- The four walkthroughs: [all-traffic-gateway.md](all-traffic-gateway.md).

## Claims this repository still pins

These rows are load-bearing. `crates/sbproxy-observe/tests/comparison_claims.rs` and `crates/sbproxy-platform/tests/proxy_protocol_wiring.rs` fail the build if they disappear or get a naked "Yes" they have not earned.

| Capability | SBproxy |
|---|---|
| Clustering substrate (gossip mesh, no Postgres) | Yes |
| Rate limiting | Built-in (node-local; cluster-wide needs a shared backend) |
| PROXY protocol | No (v1 parser present, not wired to a listener) |

Cluster-wide spend and rate counters are coherent within a bounded staleness window on the gossip mesh; exact enforcement under a concurrent burst needs a shared backend. Do not read the clustering row as "every counter is exact with no Redis."

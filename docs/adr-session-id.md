# ADR: Session ID propagation (Wave 8 / T2.1)

*Last modified: 2026-04-28*

## Status

Accepted. Builds on `adr-event-envelope.md` (T5.1).

## Context

Sessions group requests that belong to one logical interaction: a multi-turn chat thread, an agent loop spanning several tool calls, or a workflow orchestrated client-side. The portal's Sessions view, per-session cost rollups, and replay are blocked on the proxy capturing this signal at the edge.

We get one cheap chance to stamp a session ID at request entry. Retrofitting it later requires every storage layer to gain a "fix-up" path, so we land it now.

## Decision

### Identifier

ULIDs (26-char Crockford-base32, lexicographically sortable by time). One canonical format, no UUID alternative path.

### Header names

| Header | Direction | Meaning |
|---|---|---|
| `X-Sb-Session-Id` | request | Caller-supplied session ID. Validated as a ULID. |
| `X-Sb-Parent-Session-Id` | request | Optional. Names the parent session this request continues from (agent sub-session, replay, fork). |
| `X-Sb-Session-Id` | response | Echoed back when a session ID was captured (caller-supplied or auto-generated). Lets stateless SDK callers learn their freshly-minted session ID. |

### Auto-generation rule

Per-origin config:

```yaml
sessions:
  capture: true              # default true; enables capture of caller-supplied session IDs
  auto_generate: anonymous   # one of: never | anonymous | always
  ttl_seconds: 86400         # 24 h default; bounds session-index lifetime
```

- `never`: only caller-supplied IDs are captured. No header in the response unless the caller supplied one.
- `anonymous` (default for AI gateway origins): if the caller did not supply a session ID **and** the request has no `user_id` resolved (T3), generate a fresh ULID and echo it back. Anonymous traffic gets one session per "burst" rather than one session per request.
- `always`: every request that arrives without a session ID gets a fresh one. Use only for systems where each request really is its own session.

Auto-generation never overwrites a caller-supplied value.

### Parent linking

`X-Sb-Parent-Session-Id` is captured into `RequestEvent.parent_session_id` verbatim. We do not validate that the parent session exists; that is the portal's job at query time. The proxy only enforces ULID format.

The portal's session view reconstructs the tree client-side from `(session_id, parent_session_id)` pairs.

### Validation

Both headers are validated as ULIDs:

```text
26 chars, charset = [0-9A-HJKMNP-TV-Z], no padding
```

Invalid values are dropped (not auto-corrected, not 4xx'd) and counted via `sbproxy_session_dropped_total{reason}` with `reason ∈ {invalid_format, too_long, empty}`. Auto-generation falls back to "as if the caller supplied nothing".

### Scripting and budget exposure

`session_id` is exposed read-only to CEL/Lua/JS/WASM (`req.session_id`). Scripts can read it for routing decisions but cannot mutate it.

`session` joins `workspace`, `key`, `user`, `origin` as a budget scope. Existing `BudgetScope` enum gains a `Session` variant; the budget engine's per-scope counter map keys on the captured `session_id`. When `auto_generate == anonymous`, anonymous traffic still gets per-session budgets (effective per-burst rate limiting for unauthenticated callers).

### Storage (T2.4 sketch, full design lives in enterprise repo)

Enterprise sessions index keys on `(workspace_id, session_id)` and stores the rollup tuple `(first_seen_ms, last_seen_ms, request_count, total_cost_micros, total_tokens_in, total_tokens_out)`. The index is a `PersistentKv` with TTL governed by `sessions.ttl_seconds`. Hot-key protection (T3.4-style) caps per-session writes per second at 200 rps; over-cap requests still emit events but skip the rollup write and increment `sbproxy_session_rollup_throttled_total`.

### Cardinality safety

Like `properties`, `session_id` is **not** a Prometheus metric label. We expose `sbproxy_session_count_distinct` (HLL estimate) for ops; never `sbproxy_requests_total{session_id=...}`.

## Consequences

- Cheap edge capture: header validation and one BTreeMap insert in `RequestEvent`.
- Anonymous-session auto-generation lets us deliver Sessions UX from day one without forcing every customer to instrument their SDK.
- The session budget scope gives operators a per-conversation rate limit, which Helicone does not expose.
- Sessions index is bounded by TTL; we are not on the hook for forever-retention session graphs.

## References

- `docs/PORTAL.md` sec 6.2.
- `docs/adr-event-envelope.md`.
- ULID spec: <https://github.com/ulid/spec>.

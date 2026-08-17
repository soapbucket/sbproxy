# Body-based routing

*Last modified: 2026-08-08*

![Body-based routing](../../docs/assets/body-routing.gif)

A single origin on `llm.local` routes each request on the `model` field of its JSON body. Two forward rules carry a `body` matcher that addresses the field with an RFC 6901 JSON Pointer (`/model`) and compares it by prefix: `gpt-` models land on one inline child origin, `claude-` models on another, and everything else falls through to the default action that proxies to `test.sbproxy.dev/anything`. Both child origins are `static` stubs standing in for dedicated model pools so the example runs with no upstream of its own.

The body is buffered (up to 64 KiB) before the route is chosen and replayed upstream byte for byte, so routing on it does not consume it. Origins without a body matcher never buffer anything. A body the matcher cannot read (not JSON, no `model` field, over the cap) is a miss, not an error: the request takes the default action exactly as it would have without the rule.

## Run

```bash
make run CONFIG=examples/body-routing/sb.yml
```

No env vars required. The proxy binds to `127.0.0.1:8080`; use the `Host: llm.local` header to land on this origin.

## Try it

A `model` starting with `gpt-` selects the gpt pool. The response is the gpt child origin's JSON banner (`"pool": "gpt"`):

```bash
curl -s -H 'Host: llm.local' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
```

A `model` starting with `claude-` selects the claude pool instead (`"pool": "claude"`):

```bash
curl -s -H 'Host: llm.local' -H 'Content-Type: application/json' \
  -d '{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}' \
  http://127.0.0.1:8080/v1/chat/completions
```

Any other model falls through to the default action, which proxies to `test.sbproxy.dev/anything`; the reply is that upstream's request echo:

```bash
curl -s -H 'Host: llm.local' -H 'Content-Type: application/json' \
  -d '{"model":"mistral-large"}' \
  http://127.0.0.1:8080/v1/chat/completions
```

A body that is not JSON misses the matcher the same way and also takes the default action:

```bash
curl -s -H 'Host: llm.local' -H 'Content-Type: text/plain' \
  -d 'model=gpt-4o' \
  http://127.0.0.1:8080/v1/chat/completions
```

## What this exercises

- `forward_rules` with a `body` matcher - route selection on a JSON body field
- `pointer: /model` - RFC 6901 JSON Pointer addressing into the request body
- `prefix:` comparison - grouping a model family under one route
- Miss-not-fail semantics - non-JSON bodies and missing fields fall through to the default action
- Replay buffering - the routed request body reaches the upstream unchanged

## See also

- [docs/configuration.md](../../docs/configuration.md) - the `body` matcher fields under Forward rules
- [examples/forward-rules/](../forward-rules/) - path-, header-, and query-based dispatch
- [docs/features.md](../../docs/features.md) - full feature reference

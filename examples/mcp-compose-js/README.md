# MCP tool composition, shaped with JavaScript

*Last modified: 2026-08-18*

Identical to [`examples/mcp-compose`](../mcp-compose/): the same
two-step DAG against `test.sbproxy.dev`'s `hello`/`echo` tools, the
same `condition`, the same RBAC and evidence config. The only
difference is `response.js` instead of `response.lua`, to show that
both response-shaping engines bind the same `ctx = {args, steps}`
context. Read that example's README first; this page only calls out
what's different.

## The shaping script

```js
(() => {
  const greeting = ctx.steps.hello.body.result.content[0].text;
  const result = { greeting };
  const echo = ctx.steps.echo;
  if (echo && echo.body) {
    result.echoed = echo.body.result.content[0].text;
  }
  return result;
})()
```

Two differences from the Lua version worth naming:

- **No top-level `return`.** QuickJS evaluates `response.js` as a
  single expression, the same convention `response_cache`'s
  `key_event`/`admit_event` JavaScript scripts use (see
  [scripting.md](../../docs/scripting.md#cache-decision-events)): a
  script with branches wraps itself in an immediately invoked function
  so the whole thing is still one expression.
- **Zero-indexed arrays.** `content[0]` here, `content[1]` in the Lua
  version, for the exact same JSON array: JavaScript indexes from 0,
  Luau tables index from 1.

## Run

```bash
sbproxy serve -f examples/mcp-compose-js/sb.yml
```

## Call and outcome

Same calls, same outcomes as the Call section of
[`examples/mcp-compose`](../mcp-compose/): swap
`compose.greet_and_echo` / `compose.ping` in against
`http://127.0.0.1:8080` with `Host: mcp.example.com` as before, and
`mcp-compose-js-events.ndjson` fills the same way
`mcp-compose-events.ndjson` does there.

## What this exercises

- `response.js` over `ctx = {args, steps}`, the JavaScript twin of
  `response.lua`
- The QuickJS sandbox's expression-evaluation entry convention
- Everything the What this exercises section of
  [`examples/mcp-compose`](../mcp-compose/) already exercises, unchanged

## See also

- [`examples/mcp-compose`](../mcp-compose/) - the Lua version, and the
  full walkthrough (config, calls, RBAC denial, evidence)
- [`docs/mcp-compose.md`](../../docs/mcp-compose.md) - the shaping
  reference for `template`, `js`, and `lua` alike

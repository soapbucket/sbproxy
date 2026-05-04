# Lua JSON transform

*Last modified: 2026-04-27*

Demonstrates the `lua_json` transform. The script entrypoint is `function modify_json(data, ctx)` where `data` is the decoded JSON value (a Lua table), not a string. A self-contained `static` action seeds the input so the example runs offline. The script uppercases `title`, derives a `word_count` field from the `body`, drops `body`, and stamps `transformed_by = "lua"` before returning the modified table for the proxy to re-serialise to JSON. The origin is reached on `127.0.0.1:8080` via the `lua.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {
#   "id": 1,
#   "title": "lua transforms keep their cool",
#   "body": "the lua script will count these eight words",
#   "userId": 7
# }

# Client response after the lua_json transform
$ curl -s -H 'Host: lua.local' http://127.0.0.1:8080/ | jq
{
  "id": 1,
  "title": "LUA TRANSFORMS KEEP THEIR COOL",
  "userId": 7,
  "word_count": 8,
  "transformed_by": "lua"
}
```

```bash
# title is uppercased
$ curl -s -H 'Host: lua.local' http://127.0.0.1:8080/ | jq -r '.title'
LUA TRANSFORMS KEEP THEIR COOL
```

```bash
# body is gone, replaced by the derived word_count
$ curl -s -H 'Host: lua.local' http://127.0.0.1:8080/ | jq 'has("body"), .word_count'
false
8
```

```bash
# Provenance tag is added
$ curl -s -H 'Host: lua.local' http://127.0.0.1:8080/ | jq -r '.transformed_by'
lua
```

## What this exercises

- `lua_json` transform with the canonical `function modify_json(data, ctx)` entrypoint
- Reading and mutating a parsed JSON table directly inside Lua (no string parsing)
- Field derivation (`word_count` from `body`), mutation (`string.upper`), and removal (`data.body = nil`)
- `static` action - inline JSON body so the example runs offline

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/scripting.md](../../docs/scripting.md) - Lua, JavaScript, and CEL scripting reference

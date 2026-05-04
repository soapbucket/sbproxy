# JavaScript body transform

*Last modified: 2026-04-27*

Demonstrates the `javascript` transform via QuickJS. The entrypoint is `function transform(body)` where `body` is the raw upstream body as a string. The script parses it as JSON, mutates the document, and returns a new JSON string. A `static` action seeds the input so the example runs offline. The script computes `title_length`, adds a reversed copy of the title, trims `body` to 40 characters with an ellipsis, and stamps `transformed_by = "javascript"`. The origin is reached on `127.0.0.1:8080` via the `js.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {
#   "id": 1,
#   "title": "javascript runs on the request path",
#   "body": "this body is longer than forty characters so it will be trimmed by the script",
#   "userId": 7
# }

# Client response after the javascript transform
$ curl -s -H 'Host: js.local' http://127.0.0.1:8080/ | jq
{
  "id": 1,
  "title": "javascript runs on the request path",
  "body": "this body is longer than forty character...",
  "userId": 7,
  "title_length": 35,
  "title_reversed": "htap tseuqer eht no snur tpircsavaj",
  "transformed_by": "javascript"
}
```

```bash
# title_length matches the source title length (no rename)
$ curl -s -H 'Host: js.local' http://127.0.0.1:8080/ | jq '.title_length'
35
```

```bash
# body is trimmed to 40 chars + "..."
$ curl -s -H 'Host: js.local' http://127.0.0.1:8080/ | jq -r '.body | length'
43
```

```bash
# Provenance tag is added
$ curl -s -H 'Host: js.local' http://127.0.0.1:8080/ | jq -r '.transformed_by'
javascript
```

## What this exercises

- `javascript` transform via QuickJS with the canonical `function transform(body)` entrypoint
- String-shaped input: the script parses and re-serialises the JSON itself (`JSON.parse` / `JSON.stringify`)
- Field derivation, slicing, and provenance stamping
- `static` action - inline JSON body so the example runs offline

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/scripting.md](../../docs/scripting.md) - Lua, JavaScript, and CEL scripting reference

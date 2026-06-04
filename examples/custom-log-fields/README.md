# custom-log-fields

Operator-defined custom access-log fields. `observability.log.custom_fields:` adds keys to each access line's `custom` object, computed per request from either a static value with `${...}` variable interpolation or a script (CEL, Lua, or JS) evaluated against the request context. Use it to pivot logs on dimensions the built-in schema does not carry (region, deployment, a derived tier, a routing decision) without forking the binary.

## Run

```bash
REGION=us-east-1 make run CONFIG=examples/custom-log-fields/sb.yml
```

## Test

```bash
curl -s -H 'Host: api.local' -H 'X-Tier: gold' http://127.0.0.1:8080/anything | head -c 40
```

The access line on the proxy's stdout carries a `custom` object:

```json
{"timestamp":"...","origin":"api.local","method":"GET","path":"/anything","status":200,"custom":{"region":"us-east-1","caller_tier":"gold","route_class":"read","upper_method":"GET"}}
```

## Field kinds

| Field | Kind | Notes |
|---|---|---|
| `region` | static `value` | `${env.REGION}` interpolation. Other variables: `${tenant_id}`, `${method}`, `${path}`, `${host}`, `${status}`, `${provider}`, `${model}`, `${request.header.NAME}`, `${attribution.KEY}`. |
| `caller_tier` | CEL `source` | Top-level context keys (`request`, `response`, `tenant_id`, `provider`, `model`, `attribution`) are in scope. |
| `route_class` | Lua `source` | The whole context is the `ctx` global; the script returns the value to log. |
| `upper_method` | JS `source` | Same `ctx` global; returns a string. |

## Rules

- Each field sets exactly one of `value` or (`source` + `engine`); both or neither is a config error.
- `engine` is one of `cel`, `lua`, `js`. WASM is not supported for log fields (it is a compiled module, not inline source).
- Field names must be unique. A field whose script errors (or whose variable does not resolve) is omitted from the line rather than failing the request.
- Custom values pass through the same redaction as every other field.
- Resolved at proxy scope today; origin and tenant scopes compose the same way once their observability-log plumbing is consumed at runtime.

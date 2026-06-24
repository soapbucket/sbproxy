# custom-log-fields

![custom-log-fields](../../docs/assets/custom-log-fields.gif)

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
{"timestamp":"...","origin":"api.local","method":"GET","path":"/anything","status":200,"custom":{"caller_tier":"gold","region":"us-east-1","scope":"origin:api.local","tenant_tag":"acme"}}
```

## Field kinds

| Field | Kind | Notes |
|---|---|---|
| `region` | static `value` | `${env.REGION}` interpolation. Other variables: `${tenant_id}`, `${method}`, `${path}`, `${host}`, `${status}`, `${provider}`, `${model}`, `${request.header.NAME}`, `${attribution.KEY}`. |
| `caller_tier` | CEL `source` | Top-level context keys (`request`, `response`, `tenant_id`, `provider`, `model`, `attribution`) are in scope. |
| `scope` | static `value` | Defined at proxy, tenant, and origin scope to show precedence. |
| `tenant_tag` | static `value` | Defined only at tenant scope. |

Scripts also support Lua (`return` the value) and JS (evaluate to the value); the whole request context is the `ctx` global.

## Scopes

Fields can be declared at three scopes and compose per request as **proxy then tenant then origin**: a more-specific scope's field overrides a less-specific field of the same `name`. In this example `scope` is defined at all three (`proxy`, `tenant:acme`, `origin:api.local`); because `api.local` is bound to tenant `acme` and defines an origin-scope `scope`, the logged value is `origin:api.local`. `region` and `caller_tier` come from the proxy scope; `tenant_tag` from the tenant scope.

## Rules

- Each field sets exactly one of `value` or (`source` + `engine`); both or neither is a config error.
- `engine` is one of `cel`, `lua`, `js`. WASM is not supported for log fields (it is a compiled module, not inline source).
- Field names must be unique within a scope. A field whose script errors (or whose variable does not resolve) is omitted from the line rather than failing the request.
- Custom values pass through the same redaction as every other field.

# Template transform (minijinja)

*Last modified: 2026-04-27*

Demonstrates the `template` transform. A `static` action emits a JSON document describing an order; the `template` transform parses that JSON as the input context and renders a minijinja template producing a human-readable plaintext receipt. A `response_modifier` rewrites `Content-Type` to `text/plain; charset=utf-8`. The origin is reached on `127.0.0.1:8080` via the `tmpl.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {
#   "order_id": "ORD-1042",
#   "customer": "Ada Lovelace",
#   "items": [
#     {"name":"Analytical Engine","qty":1,"price":9999.0},
#     {"name":"Punch Cards (1000-pack)","qty":3,"price":14.5}
#   ],
#   "total": 10042.5
# }

# Client response after the template transform
$ curl -i -H 'Host: tmpl.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8

Order ORD-1042 for Ada Lovelace
----
1 x Analytical Engine @ $9999
3 x Punch Cards (1000-pack) @ $14.5
----
Total: $10042.5
```

```bash
# Same response served as plain text - useful for receipts, email bodies, logs
$ curl -s -H 'Host: tmpl.local' http://127.0.0.1:8080/
Order ORD-1042 for Ada Lovelace
----
1 x Analytical Engine @ $9999
3 x Punch Cards (1000-pack) @ $14.5
----
Total: $10042.5
```

## What this exercises

- `template` transform - minijinja rendering with the upstream JSON as the context
- minijinja control flow (`{%- for item in items %}`) and variable interpolation
- `response_modifiers` rewriting `Content-Type` to `text/plain; charset=utf-8`
- `static` action - inline JSON body so the example runs offline

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

# String replacement transform

*Last modified: 2026-04-27*

Demonstrates the `replace_strings` transform. Two find-and-replace rules run against the upstream body: a literal substring swap that rewrites every occurrence of `internal.example.com` to `public.example.com`, and a regex pattern that redacts any 16-digit run (e.g., a card number) with `[REDACTED]`. A `static` action seeds a JSON body containing both patterns so the example is self-contained. The origin is reached on `127.0.0.1:8080` via the `replace.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Upstream body (what the static action emits internally):
# {
#   "endpoint": "https://internal.example.com/v1/charges",
#   "card": "4242424242424242",
#   "note": "internal.example.com is the source of truth"
# }

# Client response after the replace_strings transform
$ curl -s -H 'Host: replace.local' http://127.0.0.1:8080/
{
  "endpoint": "https://public.example.com/v1/charges",
  "card": "[REDACTED]",
  "note": "public.example.com is the source of truth"
}
```

```bash
# Both occurrences of internal.example.com are rewritten
$ curl -s -H 'Host: replace.local' http://127.0.0.1:8080/ | grep -oE '(internal|public)\.example\.com' | sort | uniq -c
   2 public.example.com
```

```bash
# 16-digit number is gone; literal redaction marker is present
$ curl -s -H 'Host: replace.local' http://127.0.0.1:8080/ | grep -E '\[REDACTED\]'
  "card": "[REDACTED]",
```

## What this exercises

- `replace_strings` transform with both literal and regex (`regex: true`) replacements
- Body-level redaction pattern: rewrite hostnames, redact card numbers in one pipeline
- `static` action emitting an inline JSON body so no upstream is needed

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

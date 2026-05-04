# HTML to Markdown transform

*Last modified: 2026-04-27*

Demonstrates the `html_to_markdown` transform. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and converts the HTML body into Markdown using ATX-style headings (`#`, `##`, ...). A `response_modifier` rewrites the `Content-Type` header to `text/markdown; charset=utf-8` so the body is delivered with the right MIME. Useful for feeding HTML into LLM pipelines that prefer Markdown, or for archiving pages in a portable format. The origin is reached on `127.0.0.1:8080` via the `tomd.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Original upstream is HTML
$ curl -s https://httpbin.org/html | head -5
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
```

```bash
# Proxied response is Markdown with ATX headings
$ curl -i -H 'Host: tomd.local' http://127.0.0.1:8080/html
HTTP/1.1 200 OK
content-type: text/markdown; charset=utf-8

# Herman Melville - Moby-Dick

Availing himself of the mild, summer-cool weather that now reigned in these latitudes, ...
```

```bash
# Heading style is ATX - look for leading hashes, not setext underlines
$ curl -s -H 'Host: tomd.local' http://127.0.0.1:8080/html | grep -E '^#'
# Herman Melville - Moby-Dick
```

## What this exercises

- `html_to_markdown` transform with `heading_style: atx`
- `response_modifiers` rewriting `Content-Type` so the body is delivered as `text/markdown`
- Composition with the `proxy` action - HTML upstream, Markdown downstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

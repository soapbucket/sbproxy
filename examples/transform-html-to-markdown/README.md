# HTML to Markdown transform

*Last modified: 2026-08-16*

![HTML to Markdown transform](../../docs/assets/transform-html-to-markdown.gif)

Demonstrates the `html_to_markdown` transform. The proxy fetches `https://test.sbproxy.dev/html` (a small fixed-shape HTML fixture the project serves for this purpose) and converts the HTML body into Markdown using ATX-style headings (`#`, `##`, ...). A `response_modifier` rewrites the `Content-Type` header to `text/markdown; charset=utf-8` so the body is delivered with the right MIME. Useful for feeding HTML into LLM pipelines that prefer Markdown, or for archiving pages in a portable format. The origin is reached on `127.0.0.1:8080` via the `tomd.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Original upstream is HTML
$ curl -s https://test.sbproxy.dev/html | head -5
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>test.sbproxy.dev sample</title></head>
<body>
  <h1>Sample HTML</h1>
```

```bash
# Proxied response is Markdown with ATX headings
$ curl -i -H 'Host: tomd.local' http://127.0.0.1:8080/html
HTTP/1.1 200 OK
content-type: text/markdown; charset=utf-8

# Sample HTML

This document exists so sbproxy HTML transforms have a fixed-shape upstream to point at.

- One
- Two
- Three

Visit [sbproxy.dev](https://sbproxy.dev) for docs.
```

```bash
# Heading style is ATX - look for leading hashes, not setext underlines
$ curl -s -H 'Host: tomd.local' http://127.0.0.1:8080/html | grep -E '^#'
# Sample HTML
```

## What this exercises

- `html_to_markdown` transform with `heading_style: atx`
- `response_modifiers` rewriting `Content-Type` so the body is delivered as `text/markdown`
- Composition with the `proxy` action - HTML upstream, Markdown downstream

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

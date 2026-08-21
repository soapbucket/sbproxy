# HTML transform

*Last modified: 2026-08-21*

![HTML transform](../../docs/assets/transform-html.gif)

Demonstrates the `html` transform on a real upstream. The proxy fetches `https://test.sbproxy.dev/html` (a small fixed-shape sample page maintained for exactly this kind of example) and rewrites the HTML in flight: it removes the upstream `<h1>`, injects a stylesheet `<link>` at the end of `<head>`, prepends a banner `<div>` at the start of `<body>`, and stamps `data-rewritten="true"` on every `<p>`. The origin is reached on `127.0.0.1:8080` via the `html.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Original upstream response (no proxy)
$ curl -s https://test.sbproxy.dev/html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>test.sbproxy.dev sample</title></head>
<body>
  <h1>Sample HTML</h1>
  <p>This document exists so sbproxy HTML transforms have a fixed-shape upstream to point at.</p>
  <ul><li>One</li><li>Two</li><li>Three</li></ul>
  <p>Visit <a href="https://sbproxy.dev">sbproxy.dev</a> for docs.</p>
</body>
</html>
```

```bash
# Proxied response: h1 removed, stylesheet injected at head_end, banner at body_start
$ curl -s -H 'Host: html.local' http://127.0.0.1:8080/html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>test.sbproxy.dev sample</title><link rel="stylesheet" href="https://cdn.example.com/sbproxy.css"></head>
<body><div id="sb-banner">Served via sbproxy</div>
  
  <p data-rewritten="true">This document exists so sbproxy HTML transforms have a fixed-shape upstream to point at.</p>
  <ul><li>One</li><li>Two</li><li>Three</li></ul>
  <p data-rewritten="true">Visit <a href="https://sbproxy.dev">sbproxy.dev</a> for docs.</p>
</body>
</html>
```

```bash
# Every matching <p> carries data-rewritten="true".
$ curl -s -H 'Host: html.local' http://127.0.0.1:8080/html | grep -oE '<p[^>]*>'
<p data-rewritten="true">
<p data-rewritten="true">
```

## What this exercises

- `html` transform - structural HTML rewriting via CSS selectors
- `remove_selectors` - element deletion (`h1` here)
- `inject` with `position: head_end` and `position: body_start` - inserting markup at fixed anchors
- `rewrite_attributes` - attribute stamping on every tag matching a selector
- Composition with the `proxy` action so the rewrite is applied on top of a real upstream response

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

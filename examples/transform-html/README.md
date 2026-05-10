# HTML transform

*Last modified: 2026-04-27*

Demonstrates the `html` transform on a real upstream. The proxy fetches `https://httpbin.org/html` (a public Moby-Dick excerpt page) and rewrites the HTML in flight: it removes the upstream `<h1>`, injects a stylesheet `<link>` at the end of `<head>`, prepends a banner `<div>` at the start of `<body>`, and stamps `data-rewritten="true"` on every `<p>`. The origin is reached on `127.0.0.1:8080` via the `html.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Original upstream response (no proxy)
$ curl -s https://httpbin.org/html | head -10
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
      <h1>Herman Melville - Moby-Dick</h1>

      <div>
        <p>...</p>
```

```bash
# Proxied response: h1 removed, stylesheet injected at head_end, banner at body_start
$ curl -s -H 'Host: html.local' http://127.0.0.1:8080/html | head -15
<!DOCTYPE html>
<html>
  <head>
  <link rel="stylesheet" href="https://cdn.example.com/sbproxy.css"></head>
  <body><div id="sb-banner">Served via sbproxy</div>

      <div>
        <p data-rewritten="true">...</p>
```

```bash
# Every paragraph carries data-rewritten="true"
$ curl -s -H 'Host: html.local' http://127.0.0.1:8080/html | grep -oE '<p[^>]*>' | head -3
<p data-rewritten="true">
<p data-rewritten="true">
<p data-rewritten="true">
```

## What this exercises

- `html` transform - structural HTML rewriting via CSS selectors
- `remove_selectors` - element deletion (`h1` here)
- `inject` with `position: head_end` and `position: body_start` - inserting markup at fixed anchors
- `rewrite_attributes` - attribute stamping across every match of a selector
- Composition with the `proxy` action so the rewrite is applied on top of a real upstream response

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

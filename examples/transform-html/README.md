# HTML transform

*Last modified: 2026-08-16*

![HTML transform](../../docs/assets/transform-html.gif)

Demonstrates the `html` transform on a real upstream. The proxy fetches `https://test.sbproxy.dev/html` (a small fixed-shape sample page maintained for exactly this kind of example) and rewrites the HTML in flight: it removes the upstream `<h1>`, injects a stylesheet `<link>` at the end of `<head>`, prepends a banner `<div>` at the start of `<body>`, and stamps `data-rewritten="true"` on a `<p>`. The origin is reached on `127.0.0.1:8080` via the `html.local` Host header.

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
  <p>Visit <a href="https://sbproxy.dev">sbproxy.dev</a> for docs.</p>
</body>
</html>
```

```bash
# Only the first matching <p> carries data-rewritten="true", not every one.
# rewrite_attributes only stamps the first tag it finds that lacks the
# attribute; it does not add the attribute to every match of the selector
# unless every match already carries some value of that attribute (in
# which case it rewrites all of them). See the note below.
$ curl -s -H 'Host: html.local' http://127.0.0.1:8080/html | grep -oE '<p[^>]*>'
<p data-rewritten="true">
<p>
```

## What this exercises

- `html` transform - structural HTML rewriting via CSS selectors
- `remove_selectors` - element deletion (`h1` here)
- `inject` with `position: head_end` and `position: body_start` - inserting markup at fixed anchors
- `rewrite_attributes` - attribute stamping on tags matching a selector
- Composition with the `proxy` action so the rewrite is applied on top of a real upstream response

## Known limitation: `rewrite_attributes` only touches the first new match

When the target attribute is not already present on any matching tag,
`rewrite_attributes` adds it to only the *first* tag the selector matches,
not to every one, despite the config surface reading like a blanket
stamp. It only rewrites *every* match when the attribute is already
present (with any value) on every one of those tags; adding a brand-new
attribute to a set of tags that do not yet carry it stops after the first
hit. On this example's live upstream page there are two `<p>` elements
and only the first gets `data-rewritten="true"`; the second is left
untouched. This looks like a bug in
`crates/sbproxy-modules/src/transform/markup.rs::rewrite_attr` (the
"attribute was not found on any matching tag" fallback branch calls
`Regex::find`, which stops at the first match, instead of adding the
attribute to every match).

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

# Markdown to HTML transform

*Last modified: 2026-08-16*

![Markdown to HTML transform](../../docs/assets/transform-markdown.gif)

Demonstrates the `markdown` transform. A `static` action returns a Markdown release-notes document; the transform converts it to HTML using pulldown-cmark with `smart_punctuation`, `tables`, and `strikethrough` enabled. A `response_modifier` rewrites the `Content-Type` to `text/html; charset=utf-8` so browsers and curl render the result correctly. The origin is reached on `127.0.0.1:8080` via the `md.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Upstream body is Markdown source. Client receives rendered HTML.
$ curl -i -H 'Host: md.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<h1>sbproxy release notes</h1>
<p>Welcome to the “April” build. Here’s what shipped:</p>
<ul>
<li>Faster startup</li>
<li><del>Buggy retries</del> Retries now respect the budget</li>
<li>New transform pipeline</li>
</ul>
<h2>Supported transforms</h2>
<table><thead><tr><th>Type</th><th>Body shape</th></tr></thead><tbody>
<tr><td>json</td><td>object</td></tr>
<tr><td>markdown</td><td>text</td></tr>
<tr><td>html</td><td>text</td></tr>
</tbody></table>
```

pulldown-cmark emits literal Unicode curly-quote characters, not HTML entities
(`&ldquo;` etc. never appear); `Content-Type` also comes back with the exact
casing the `response_modifiers.headers.set` key used, not lowercased.

```bash
# Smart punctuation converts straight quotes to curly (U+201C/U+201D/U+2019).
# (A `[...]` character class spanning multiple multi-byte UTF-8 characters is
# unreliable on BSD grep/macOS; alternation works, and `sort -u` on some
# locales collates distinct quote glyphs as equal, so this skips both.)
$ curl -s -H 'Host: md.local' http://127.0.0.1:8080/ | grep -oE '“|”|’'
“
”
’
```

```bash
# Strikethrough renders as <del>
$ curl -s -H 'Host: md.local' http://127.0.0.1:8080/ | grep -oE '<del>[^<]+</del>'
<del>Buggy retries</del>
```

## What this exercises

- `markdown` transform with `smart_punctuation`, `tables`, and `strikethrough`
- pulldown-cmark rendering Markdown to HTML at the proxy boundary
- `response_modifiers` rewriting `Content-Type` so the rendered HTML is served as `text/html`
- `static` action - inline Markdown body so the example runs offline

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

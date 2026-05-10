# Markdown to HTML transform

*Last modified: 2026-04-27*

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
content-type: text/html; charset=utf-8

<h1>sbproxy release notes</h1>
<p>Welcome to the &ldquo;April&rdquo; build. Here&rsquo;s what shipped:</p>
<ul>
<li>Faster startup</li>
<li><del>Buggy retries</del> Retries now respect the budget</li>
<li>New transform pipeline</li>
</ul>
<h2>Supported transforms</h2>
<table>
<thead><tr><th>Type</th><th>Body shape</th></tr></thead>
<tbody>
<tr><td>json</td><td>object</td></tr>
<tr><td>markdown</td><td>text</td></tr>
<tr><td>html</td><td>text</td></tr>
</tbody>
</table>
```

```bash
# Smart punctuation converts straight quotes to curly
$ curl -s -H 'Host: md.local' http://127.0.0.1:8080/ | grep -oE '&[lr]squo;|&[lr]dquo;' | sort -u
&ldquo;
&lsquo;
&rdquo;
&rsquo;
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

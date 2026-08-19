# CSS transform

Sometimes the stylesheet you serve is not the stylesheet you want. A staging build ships a debug banner, a vendor origin sets a color you need to override, or a bundle carries comments you would rather not send. The `css` transform edits stylesheet responses at the edge: it removes rule blocks by selector, appends rules of your own, and optionally minifies, all in one pass and without redeploying the origin.

This example seeds a stylesheet with a static action and rewrites it.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

The origin serves a stylesheet with a leading comment, a `.debug-banner` rule, and a `body` rule. The transform removes `.debug-banner`, appends a `.footer` rule, and minifies, which also drops the comment:

```bash
$ curl -i -H 'Host: css.local' http://127.0.0.1:8080/styles.css
HTTP/1.1 200 OK
content-type: text/css
content-length: 89

body{font-family:system-ui, sans-serif;color:#0a1733;}.footer{color:#555;font-size:12px;}
```

The `.debug-banner` block and the `/* site stylesheet, staging build */` comment are gone, the `body` rule survives, and the injected `.footer` rule is appended, all on one minified line.

## What this shows

- `remove_selectors` deleting a named rule block
- `inject` appending a rule
- `minify` collapsing whitespace and stripping comments

The three run in that order: remove, then inject, then minify. Drop `minify` to keep the output readable, or drop `remove_selectors` and `inject` to use it purely as a minifier.

## See also

- [docs/transforms.md](../../docs/transforms.md) is the full transform reference.
- [examples/transform-html](../transform-html/) is the same shape for HTML bodies.

# PDF to Markdown transform

*Last modified: 2026-08-22*

Demonstrates the `pdf_markdown` transform: an `application/pdf` upstream response is decoded and replaced with a Markdown projection (the same `MarkdownProjection { body, title, token_estimate }` shape [`transform-html-to-markdown`](../transform-html-to-markdown/) produces), so a downstream JSON envelope or `x-markdown-tokens` header sees the same shape whether the origin served HTML or PDF.

This transform is gated behind the `transform-pdf` cargo feature, off by default. `pdf-extract` and `lopdf`, the two pure-Rust decoders it uses, together pull roughly 70 transitive crates that most deployments never need for anything else.

## Run

```bash
cargo run -p sbproxy --features sbproxy-modules/transform-pdf -- \
  serve -f sb.yml
```

A `sbproxy serve -f sb.yml` against a default build (without the feature) fails config load with a message naming `pdf_markdown` and the missing feature, rather than silently ignoring the transform.

## Try it

```bash
curl -s -H 'Host: pdf.local' http://127.0.0.1:8080/pdf
```

Returns the decoded Markdown body: page text joined by `\n\n---\n\n` horizontal rules, truncated with a `(... PDF truncated at N pages ...)` note past `max_pages`.

A corrupted or non-PDF body under `Content-Type: application/pdf` is a decode error, which follows the same `failure_posture` handling as every other transform's `Err` (`docs/transforms.md`): the corrupted bytes are never forwarded.

## What this exercises

- `pdf_markdown` transform with default `max_pages` and `token_bytes_ratio`
- The `transform-pdf` cargo feature gate, including the config-load-time refusal when it is off
- Title resolution: `/Info /Title`, then the first heading-like body line, then `"Untitled PDF"`
- `crates/sbproxy-modules/src/transform/pdf_markdown.rs`'s unit tests exercise the decode path directly (extraction, page truncation, corrupted/empty-body errors) against hand-built fixture PDFs; this example shows the same transform wired into a route.

## See also

- [docs/transforms.md](../../docs/transforms.md) - full transform reference, including `pdf_markdown`
- [transform-html-to-markdown](../transform-html-to-markdown/) - the HTML-source sibling that produces the same `MarkdownProjection` shape
- [content-for-agents](../../docs/content-for-agents.md) - the wider content-negotiation picture this projection feeds into

# Content-shape negotiation

*Last modified: 2026-05-08*

Same URL, three response shapes. The proxy reads the agent's `Accept` header on the way in, resolves a single content shape per request, and the response pipeline rewrites `Content-Type` and stamps `x-markdown-tokens` on the way out. The four-transform default chain (`boilerplate`, `html_to_markdown`, `citation_block`, `json_envelope`) does the rewrite work in place; the resolver decides which transforms run for a given request and which stay quiet.

This example uses `test.sbproxy.dev` as the upstream so the configuration is self-contained. Swap `action.url` for a real HTML upstream to drive the negotiation against a live page.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Markdown shape. The HTML body is projected into Markdown and the
# proxy stamps `Content-Type: text/markdown` plus an
# `x-markdown-tokens` header carrying the projected body's token
# estimate.
$ curl -i -H 'Host: shape.local' \
       -H 'Accept: text/markdown' \
       http://127.0.0.1:8080/article
HTTP/1.1 200 OK
content-type: text/markdown; charset=utf-8
x-markdown-tokens: 27

# The Article

The first paragraph carries the lede ...
```

```bash
# JSON envelope shape. Same Markdown projection, wrapped in the v1
# schema. `Content-Type` advertises the schema profile so a typed
# client can validate without sniffing the body.
$ curl -i -H 'Host: shape.local' \
       -H 'Accept: application/json' \
       http://127.0.0.1:8080/article
HTTP/1.1 200 OK
content-type: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"
x-markdown-tokens: 27

{
  "schema_version": "1",
  "title": "The Article",
  "content_md": "# The Article\n\nThe first paragraph ...",
  "token_estimate": 27,
  "license": "all-rights-reserved",
  "url": "https://test.sbproxy.dev/article",
  "fetched_at": "2026-05-08T12:00:00Z",
  "citation_required": false
}
```

```bash
# Raw HTML pass-through. No projection runs; the upstream body
# reaches the client unchanged. No `x-markdown-tokens` header
# because no Markdown was projected.
$ curl -i -H 'Host: shape.local' \
       -H 'Accept: text/html' \
       http://127.0.0.1:8080/article
HTTP/1.1 200 OK
content-type: text/html

<!doctype html>
<html>...</html>
```

A request with no `Accept` header (or `Accept: */*`) falls back to the origin's `default_content_shape`. This example sets it to `html`, so a curl with no header behaves like the third example above. Set `default_content_shape: markdown` to flip the default for agent-heavy traffic.

## How it works

The four transforms run in declared order. The negotiated transform shape gates which ones do work and which pass the body through:

1. `boilerplate` strips nav, footer, sidebar, and other chrome from the HTML body so the projection sees mainly the article body. Reports the byte-count it stripped on `RequestContext.metrics.stripped_bytes` for the audit trail.
2. `html_to_markdown` projects the HTML into Markdown when the negotiated shape is `markdown` or `json`. Computes a token estimate from the projected body length using the origin's `token_bytes_ratio` (default `0.25`). The estimate lands on `x-markdown-tokens` and on the envelope's `token_estimate` field; both read from the same value.
3. `citation_block` prepends a citation footer naming the upstream URL so cited Markdown is traceable back to its source. Honours `force_citation: true` when the policy needs to demand a citation regardless of negotiated shape.
4. `json_envelope` wraps the projected Markdown in the v1 JSON envelope schema when the negotiated shape is `json`. No-op for the Markdown and HTML shapes.

The single Wave 4 transform on the origin (here `json_envelope`) is the trigger that tells the compiler to synthesise an `auto_content_negotiate` config and mount the resolver. Origins that pair the chain with `ai_crawl_control` can leave `transforms:` empty, and the compiler auto-prepends the same four entries; example `17-markdown-for-agents` shows that path with a paywall in front.

## Wildcard fallback rules

`default_content_shape` controls what `Accept: */*` and a missing `Accept` header resolve to. The recognised values are `markdown`, `json`, `html`, `pdf`, and `other`; unset falls back to `html`. Q-value tie-breaks (`Accept: text/markdown;q=0.9, text/html;q=0.9`) resolve to Markdown by canonical preference order, which matches the e2e suite in `e2e/tests/content_negotiation_e2e.rs`.

## What this exercises

- `auto_content_negotiate` synthesised by the compiler when the origin authors a Wave 4 transform
- `default_content_shape: html` for the wildcard `Accept` fallback
- The four-transform default chain (`boilerplate`, `html_to_markdown`, `citation_block`, `json_envelope`) in the canonical order
- `Content-Type` rewrite and `x-markdown-tokens` header stamping in the response pipeline

## See also

- [docs/configuration.md](../../docs/configuration.md) for the full origin schema
- [examples/17-markdown-for-agents](../17-markdown-for-agents/) for the same chain wired in front of an `ai_crawl_control` paywall
- [examples/45-transform-html-to-markdown](../45-transform-html-to-markdown/) for the standalone HTML to Markdown transform without negotiation
- The e2e contract at `e2e/tests/content_negotiation_e2e.rs` and `e2e/tests/x_markdown_tokens_e2e.rs`

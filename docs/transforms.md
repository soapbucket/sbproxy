# Transforms

*Last modified: 2026-08-21*

A transform edits a response body before it reaches the client. Reach for one when the shape an upstream returns is not the shape a caller needs: trimming fields from a JSON payload, converting HTML to Markdown for an LLM, capping a body size, or running a sandboxed script or WASM module over the bytes. Transforms never touch the request; for that, see the request modifier and forward-rule sections of [configuration.md](configuration.md).

SBproxy ships 26 transform types plus `noop`. This page is the map: what a transform is, where it runs, the fields every transform shares, and a minimal working config for each kind. Full field references for the JSON/HTML/text transforms live inline below; the scripting, WASM, and agent-content transforms link out to their dedicated guides rather than duplicating them here.

## Where a transform runs

Transforms are a `response_body_filter` stage. Per [architecture.md](architecture.md)'s request pipeline:

```
response_filter:
  CORS, HSTS, security headers, response modifiers, forward rule echo,
  rate limit headers, Alt-Svc, CSRF cookie, session cookie, on_response
  callbacks, traceparent echo.

response_body_filter:
  Response cache write on miss, transform pipeline, fallback body swap.
```

So a transform chain runs after `on_response` callbacks and response header shaping have already happened, and after the response-cache write decision for that request. Each origin's chain is compiled once, at config load or reload, into an ordered `Vec` of compiled transforms; per-request execution walks that list with no allocation in the chain-construction path.

## A transform entry

Every item in an origin's `transforms:` list is wrapped in the same pipeline-level fields, on top of whatever fields its own type needs:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Transform type discriminator, e.g. `json`, `wasm`. |
| `content_types` | list | `[]` | Content-Type substrings this transform applies to. A response's `Content-Type` header must `contain` one of the listed strings for the transform to run; empty matches every content type, and a response with no `Content-Type` header never matches a non-empty list. |
| `failure_posture` | string | `open` | What happens to the response when this transform errors. `open` skips the failed transform and continues the chain with the next one. `closed` replaces the whole response body with a generic error instead of forwarding bytes the transform never finished producing. `degraded` and `observe` are rejected at config load; neither has a defined meaning for a transform yet. |
| `fail_on_error` | bool | `false` | Legacy spelling of the same axis: `true` resolves to `failure_posture: closed`, `false` to `open`. Only read when `failure_posture` is absent. Setting both to values that disagree is a config-load error. |
| `max_body_size` | int | `10485760` | Maximum body size, in bytes, this transform is willing to see. Under `open`, a larger body skips the transform and passes through unmodified; under `closed`, the response fails, because a body the transform never saw must not reach the client. |
| `disabled` | bool | `false` | When true, the transform is still parsed and validated (so a config error in a disabled transform still fails config load) but excluded from the compiled chain. |

## Chaining and order

Transforms run in the order they're listed. Each one reads the buffer the previous one left behind and writes back into the same buffer, so a later transform sees the earlier ones' output, not the original upstream body. Order is structural for some pairings: the `boilerplate` transform's own doc comment states it "must run BEFORE `HtmlToMarkdownTransform`. Doing it after Markdown projection would have nothing to strip; the projection has already discarded structural tags." The shipped four-step content-shaping chain (`boilerplate` -> `html_to_markdown` -> `citation_block` -> `json_envelope`, see [content-for-agents.md](content-for-agents.md)) follows that same logic end to end.

Two things gate whether a transform runs at all on a given response, independent of its own fields: the `content_types` filter above, and `disabled: true`.

**Response cache and request-dependent transforms.** An origin with `response_cache` enabled stores each cached entry's *transformed* body, not the raw upstream response, and a stale-while-revalidate refresh reruns the chain with no request in scope. That's only sound for a transform whose output is a pure function of the response body, its content type, and its own static config. A transform that reads request state (the scripted transforms `lua` / `lua_json` / `javascript` / `js_json`, the content-negotiation family `html_to_markdown` / `citation_block` / `json_envelope`, `cel`, `a2a_agent_card_rewrite`, and every linked-plugin transform) is refused at config load when combined with `response_cache` on the same origin; the load error names the transform. A `wasm` transform is the one type in this list that is not a constant: it only becomes request-dependent, and only then joins this refusal, when its own `request_context: true` is set (see [scripting.md §6.1](scripting.md#61-request_context-opting-a-module-into-ctx)); a `wasm` transform that leaves `request_context` unset stays cacheable. Move a refused transform to an origin without `response_cache`, or drop it from the chain, to keep the pairing.

## JSON shaping

### `json` - field manipulation

Set, remove, or rename fields on a JSON body. Order of operations inside one `json` transform is fixed: `remove` runs first, then `rename`, then `set` last (so `set` can overwrite a field that was just renamed into place).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `set` | map | `{}` | Fields to set or overwrite. Values may be any JSON. |
| `remove` | list | `[]` | Field names to delete. |
| `rename` | map | `{}` | `old_name -> new_name` mapping. |

```yaml
transforms:
  - type: json
    rename:
      userId: author_id
    remove:
      - body
    set:
      source: sbproxy
```

Verified against [`examples/transform-json/sb.yml`](../examples/transform-json/).

### `json_projection` - include/exclude fields

Keep or drop a flat field list. `fields` (alias `include`) is required; there's no nested `projection:` key.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fields` | list | required | Field names to keep (default) or drop (when `exclude` is true). Alias: `include`. |
| `exclude` | bool | `false` | When true, drop the listed fields instead of keeping them. |

```yaml
transforms:
  - type: json_projection
    fields: [id, title]
```

Verified against [`examples/transform-json-projection/sb.yml`](../examples/transform-json-projection/).

### `json_schema` - response validation

Validate the response body against a JSON Schema document, compiled once at config load. Remote `$ref` resolution is disabled to prevent SSRF.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema` | object | required | The JSON Schema document. |

```yaml
transforms:
  - type: json_schema
    fail_on_error: true
    schema:
      type: object
      required: [id, title]
      properties:
        id: { type: integer }
        title: { type: string }
```

Verified against [`examples/transform-json-schema/sb.yml`](../examples/transform-json-schema/). A validation failure only produces a rejected response when `failure_posture` is `closed` (or the legacy `fail_on_error: true`); under the `open` default, a `static` action origin logs a warning and still serves the configured body unchanged.

## Text, encoding, and format

### `template` - render the body through minijinja

Renders the JSON body as input data to a minijinja (Jinja-style) template.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `template` | string | required | Template source with `{{ variable }}` syntax. |

```yaml
transforms:
  - type: template
    template: |
      Order {{ order_id }} for {{ customer }}
```

Verified against [`examples/transform-template/sb.yml`](../examples/transform-template/).

### `replace_strings` - literal or regex find-and-replace

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replacements` | list | required | Ordered list of replacement rules. |
| `replacements[].find` | string | required | Literal substring or regex pattern. |
| `replacements[].replace` | string | required | Replacement string. |
| `replacements[].regex` | bool | `false` | When true, treat `find` as a regex. |

```yaml
transforms:
  - type: replace_strings
    replacements:
      - find: "internal.example.com"
        replace: "public.example.com"
      - find: '\d{16}'
        replace: "[REDACTED]"
        regex: true
```

Verified against [`examples/transform-replace-strings/sb.yml`](../examples/transform-replace-strings/).

### `normalize` - whitespace and newline cleanup

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trim` | bool | `false` | Trim leading and trailing whitespace. |
| `collapse_whitespace` | bool | `false` | Collapse runs of spaces and tabs into a single space. |
| `normalize_newlines` | bool | `false` | Replace `\r\n` with `\n`. |

```yaml
transforms:
  - type: normalize
    trim: true
    collapse_whitespace: true
    normalize_newlines: true
```

No example directory ships this transform in isolation; the snippet above is built directly from `NormalizeTransform`'s config struct in `crates/sbproxy-modules/src/transform/text.rs`, not from a runnable fixture.

### `encoding` - base64/URL encode or decode

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encoding` | string | required | One of `base64_encode`, `base64_decode`, `url_encode`, `url_decode`. |

```yaml
transforms:
  - type: encoding
    encoding: base64_encode
```

Verified against [`examples/transform-encoding/sb.yml`](../examples/transform-encoding/).

### `format_convert` - JSON/YAML conversion

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `from` | string | required | Source format: `json` or `yaml`. |
| `to` | string | required | Target format: `json` or `yaml`. |

```yaml
transforms:
  - type: format_convert
    from: json
    to: yaml
```

No example directory ships this transform; the snippet is built directly from `FormatConvertTransform`'s config struct.

## Body size and streaming control

### `payload_limit` - cap response size

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_size` | int | required | Maximum allowed body size in bytes. |
| `truncate` | bool | `false` | When true, truncate to `max_size`. When false, error on oversize. |

```yaml
transforms:
  - type: payload_limit
    max_size: 256
    truncate: true
```

Verified against [`examples/transform-payload-limit/sb.yml`](../examples/transform-payload-limit/).

### `discard` - drop the body entirely

Takes no fields. Replaces the body with an empty one; useful for beacon-style endpoints or forced-empty responses.

```yaml
transforms:
  - type: discard
```

### `sse_chunking` - Server-Sent Events framing

Formats the body as SSE with the configured line prefix and double-newline event delimiters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `line_prefix` | string | `"data: "` | Prefix prepended to each non-empty line. |

```yaml
transforms:
  - type: sse_chunking
    line_prefix: "data: "
```

No example directory ships this transform; the snippet is built directly from `SseChunkingTransform`'s config struct in `crates/sbproxy-modules/src/transform/control.rs`.

## HTML, Markdown, and CSS

### `html` - element removal, injection, attribute rewrites

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `remove_selectors` | list | `[]` | Tag names or `#id` selectors to strip. |
| `inject` | list | `[]` | `{position, content}` entries. `position` is `head_end`, `body_start`, or `body_end`. |
| `rewrite_attributes` | list | `[]` | `{selector, attribute, value}` entries. Every tag the selector matches is stamped: a tag that already carries the attribute has its value replaced, and a tag that does not gets the attribute added. The tag's attribute list is what gets read, so an unquoted upstream value (`<a target=_self>`) is replaced and requoted rather than duplicated, and the same characters inside a different attribute's value are left alone. |
| `format_options` | object | none | Optional post-manipulation HTML optimization (see `optimize_html` below for the sub-fields). |

```yaml
transforms:
  - type: html
    remove_selectors: [h1]
    inject:
      - position: head_end
        content: '<link rel="stylesheet" href="https://cdn.example.com/sbproxy.css">'
```

Verified against [`examples/transform-html/sb.yml`](../examples/transform-html/).

### `optimize_html` - minify

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `remove_comments` | bool | `true` | Strip `<!-- ... -->` comments. |
| `collapse_whitespace` | bool | `true` | Collapse runs of whitespace into a single space (preserves `<pre>` and `<code>` content). |
| `remove_optional_tags` | bool | `false` | Remove optional closing tags such as `</li>`, `</p>`, `</tr>` (experimental). |

```yaml
transforms:
  - type: optimize_html
```

No example directory ships this transform standalone; the snippet and defaults come directly from `OptimizeHtmlTransform`'s config struct.

### `html_to_markdown` - HTML to Markdown projection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `heading_style` | string | `"atx"` | Heading style: `atx` (`#` headings) or `setext` (underlined). |

```yaml
transforms:
  - type: html_to_markdown
    heading_style: atx
```

Verified against [`examples/transform-html-to-markdown/sb.yml`](../examples/transform-html-to-markdown/). This is also the second step of the content-shaping chain covered in [content-for-agents.md](content-for-agents.md); the two uses are the same transform.

### `markdown` - Markdown to HTML

Converts Markdown to HTML via `pulldown-cmark`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `smart_punctuation` | bool | `false` | Curly quotes, smart dashes. |
| `tables` | bool | `false` | GitHub-flavored tables. |
| `strikethrough` | bool | `false` | `~~strikethrough~~` support. |

```yaml
transforms:
  - type: markdown
    tables: true
    strikethrough: true
    smart_punctuation: true
```

Verified against [`examples/transform-markdown/sb.yml`](../examples/transform-markdown/).

### `css` - stylesheet injection and pruning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `inject` | list | `[]` | CSS rules to append. |
| `remove_selectors` | list | `[]` | Selectors whose rule blocks are removed. |
| `minify` | bool | `false` | Minify the output. |

```yaml
transforms:
  - type: css
    inject:
      - "body { background: #fafafa; }"
    remove_selectors: [".legacy-banner"]
    minify: true
```

No example directory ships this transform standalone; the snippet is from [configuration.md](configuration.md)'s Transforms reference, itself sourced from `CssTransform`'s config struct.

## Scripting transforms

Six transform types hand the body to a scripting or sandboxing engine instead of a fixed-shape config. Each is documented in depth in [scripting.md](scripting.md); this page only shows the minimal wiring.

### `lua`

Runs a Lua `transform(body, ctx)` function over the raw body string; the return value (a non-string return is JSON-serialized) replaces it. Unlike `lua_json`, the body is never parsed as JSON, so this is the transform to reach for on plain text, XML, CSV, or a body that is only sometimes JSON. Optional `function_name` picks a different entrypoint. A script with no `transform` function falls back to the legacy format: top-level code with the raw body bound to a `body` global.

```yaml
transforms:
  - type: lua
    script: |
      function transform(body, ctx)
        return string.upper(body)
      end
```

No example directory ships this transform standalone; the snippet is built directly from `LuaTransform`'s config struct in `crates/sbproxy-modules/src/transform/mod.rs`. `examples/transform-lua/sb.yml` demonstrates the JSON sibling, `lua_json`, below.

### `lua_json`

Runs a Lua `modify_json(data, ctx)` function over the parsed JSON body; the return value replaces it. Alias field: `lua_script`.

```yaml
transforms:
  - type: lua_json
    script: |
      function modify_json(data, ctx)
        data.processed = true
        return data
      end
```

Verified against [`examples/transform-lua/sb.yml`](../examples/transform-lua/).

### `javascript`

Runs a JavaScript `transform(body, ctx)` function over the raw body string (a non-string return is JSON-serialized). Optional `function_name` picks a different entrypoint.

```yaml
transforms:
  - type: javascript
    script: |
      function transform(body, ctx) {
        return body.toUpperCase();
      }
```

Verified against [`examples/transform-javascript/sb.yml`](../examples/transform-javascript/).

### `js_json`

Runs a JavaScript `modify_json(data, ctx)` function over the parsed JSON body. Optional `function_name` picks a different entrypoint. Alias field: `js_script`.

```yaml
transforms:
  - type: js_json
    script: |
      function modify_json(data, ctx) {
        data.processed = true;
        return data;
      }
```

Verified against [scripting.md](scripting.md) section 5.

### `cel`

Sets, appends, or removes *response headers* via CEL `value_expr` rules. It cannot write a response body: see [scripting.md](scripting.md#36-the-cel-response-transform) for why `on_request:` and `on_response:` were removed from this transform's config rather than kept as unenforced keys.

```yaml
transforms:
  - type: cel
    headers:
      - { op: set, name: x-served-by, value_expr: '"sbproxy"' }
      - { op: remove, name: x-internal-trace }
```

Verified against [scripting.md](scripting.md) section 3.6.

### `wasm`

Pipes the body through a sandboxed WASI module's stdin/stdout (`timeout_ms`, `max_memory_pages`, `max_fuel`, `sha256` control the sandbox). Full authoring contract, the module lifecycle, and sandbox boundaries are in [wasm-development.md](wasm-development.md).

```yaml
transforms:
  - type: wasm
    module_path: examples/wasm/echo-rust/echo.wasm
    timeout_ms: 500
    max_memory_pages: 256
```

Verified against [`examples/wasm-transform/sb.yml`](../examples/wasm-transform/).

## Content-shaping for agents

`boilerplate`, `citation_block`, and `json_envelope` exist to serve the same page as HTML to a browser and as Markdown or a structured JSON envelope to an AI agent, chained with `html_to_markdown`. Authoring any one of them (most commonly `json_envelope`) opts the origin into the compiler's `auto_content_negotiate` wiring. The full mechanism, including the `Accept`-based two-pass negotiation and the four well-known projection documents, is [content-for-agents.md](content-for-agents.md); this section only covers what each transform's own config accepts.

### `boilerplate`

Strips `<nav>`, `<footer>`, `<aside>`, and comment/ad/sidebar `<div>` blocks from HTML before a Markdown projection runs. Ships with no config fields today.

```yaml
transforms:
  - type: boilerplate
```

### `citation_block`

Prepends a Markdown citation line naming the source URL and license when the matched `ai_crawl_control` tier requires it.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `force_citation` | bool (optional) | none | Standalone override when no tier matched. `None` defers to `RequestContext::citation_required`. |

```yaml
transforms:
  - type: citation_block
    force_citation: true
```

### `json_envelope`

Wraps the Markdown projection in the versioned JSON envelope schema (`schema_version`, `title`, `url`, `license`, `content_md`, `fetched_at`, `citation_required`, `token_estimate`, and pass-through `schema_org`). Takes no config fields; it's a no-op unless the negotiated content shape is JSON and an upstream `html_to_markdown` has already populated the projection.

```yaml
transforms:
  - type: json_envelope
```

The full four-step chain, verified together, in order, with the compiler's auto-wiring note inline:

```yaml
transforms:
  - type: boilerplate
  - type: html_to_markdown
  - type: citation_block
  - type: json_envelope
```

Verified against [`examples/content-shape-negotiation/sb.yml`](../examples/content-shape-negotiation/) and [`examples/markdown-for-agents/sb.yml`](../examples/markdown-for-agents/).

## A2A agent-card rewriting

### `a2a_agent_card_rewrite`

Rewrites the `url`, `endpoint`, and nested `agent.url` fields on JSON responses served at A2A discovery paths, so a client that fetches the card keeps routing follow-up calls through the proxy instead of jumping straight at the upstream. Full discovery-flow context and the served-card precedence rules are in [a2a-gateway.md](a2a-gateway.md).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `paths` | list | the three well-known A2A discovery paths | Request paths that trigger the rewrite. An empty list collapses to the default set. |
| `proxy_host` | string (optional) | none | Hostname (or host:port) substituted into rewritten URLs. When unset, the inbound `Host` header is used. |

```yaml
transforms:
  - type: a2a_agent_card_rewrite
    paths:
      - /.well-known/agent-card.json
    proxy_host: proxy.example.com
```

No standalone example directory exercises this transform's YAML in isolation (the `a2a-protocol` and `a2a-prompt-injection` examples configure the `a2a` action, not this transform); the snippet above is from the transform's own doc comment in `crates/sbproxy-modules/src/transform/a2a_agent_card_rewrite.rs`, not a runnable fixture.

## Testing

### `noop`

Passes the body through unchanged. Real and dispatched (`compile.rs` matches `"noop"` the same as any built-in transform type), but it exists for tests and plugin scaffolding rather than production traffic shaping.

```yaml
transforms:
  - type: noop
```

## Custom transforms

A `type:` string the built-in match arms don't recognize falls through to two further tiers: a linked plugin registered via `sbproxy-plugin`'s `TransformPluginRegistration` and the `TransformHandler` trait (see [plugins.md](plugins.md)), and then a config-loaded JavaScript or WASM extension bundle attaching a `transforms[]` hook (see [extension-bundles.md](extension-bundles.md)). Both run after every built-in `type:` string has already failed to match, so a custom transform can't shadow a built-in name.

## See also

- [configuration.md](configuration.md) - full `sb.yml` field reference, including the origin schema transforms live under.
- [scripting.md](scripting.md) - CEL, Lua, JavaScript, and WASM engines, sandbox limits, and the shared `ctx` context table.
- [wasm-development.md](wasm-development.md) - authoring WASI modules for the `wasm` transform.
- [content-for-agents.md](content-for-agents.md) - the full content-negotiation and agent-content pillar that `boilerplate` / `citation_block` / `json_envelope` / `html_to_markdown` serve.
- [a2a-gateway.md](a2a-gateway.md) - A2A discovery, agent-card serving, and `a2a_agent_card_rewrite`.
- [plugins.md](plugins.md) - writing a linked `TransformHandler` plugin.
- [extension-bundles.md](extension-bundles.md) - JavaScript/WASM extension bundles that attach `transforms[]` hooks dynamically.

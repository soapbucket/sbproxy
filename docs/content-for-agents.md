# Content for agents

*Last modified: 2026-05-03*

This guide is the operator-facing companion to the content-shaping pillar. If you have SBproxy running and you have already read [configuration.md](configuration.md) and [ai-crawl-control.md](ai-crawl-control.md), this is the next document. It covers how the proxy negotiates a content shape with an agent, how the body is transformed into that shape, what license posture the proxy advertises in four well-known documents, and how operators stamp the per-route editorial signal that ties everything together.

The reader is a publisher or platform engineer who wants to turn on agent-aware content delivery. The audience is not Rust developers; the focus is configuration, wire shapes, and the operational guarantees you get for them.

## What ships

The content-shaping surface area:

- **Two-pass `Accept` resolution.** A pricing pass and a transformation pass. Agents declare a shape preference via `Accept`; the proxy matches a tier on the pricing pass and runs a body transform on the transformation pass. The two passes can diverge by design under q-value tie-breaks. See [adr-content-negotiation-and-pricing.md](adr-content-negotiation-and-pricing.md) for the contract.
- **JSON envelope.** A structured response shape for `Accept: application/json`. Wraps the page's Markdown body with title, URL, license URN, citation flag, token estimate, and pass-through schema.org JSON-LD. Versioned via the `Content-Type` profile parameter. See [adr-json-envelope-schema.md](adr-json-envelope-schema.md).
- **`Content-Signal` response header.** A per-route editorial signal in a closed value set: `ai-train`, `ai-input`, `search`. Stamped on 200 responses; consumed by RSL projections, TDMRep projections, and the JSON envelope.
- **`x-markdown-tokens` response header.** Approximate token count of the Markdown body, computed once per response and stamped on Markdown and JSON envelope responses. Same value the JSON envelope's `token_estimate` field carries.
- **Citation block transform.** Prepends a source / license / fetched-at line to Markdown bodies when the matched tier asserts `citation_required`.
- **Boilerplate stripping.** Drops navigation, footer, aside, and comment-section nodes before the HTML-to-Markdown transform runs. Cuts token counts on typical news / blog pages by 30 to 60 percent without losing article content.
- **Four projection documents.** `robots.txt`, `llms.txt` (and `llms-full.txt`), `/licenses.xml`, and `/.well-known/tdmrep.json`. Each is generated from the operator's compiled `ai_crawl_control` policy, regenerated atomically on every config reload, and served from the same hostname as the rest of the origin.
- **aipref signal parsing.** The inbound `aipref:` request header is parsed into a typed signal and surfaced to the scripting layer (CEL / Lua / JavaScript / WASM). Default-permissive when the header is absent or malformed.

## Concept map

```
+---------+   1: GET /article                       +-----------+
|  agent  |---------------------------------------->|  sbproxy  |
+---------+   Accept: text/markdown                 |           |
     |                                              +-----+-----+
     |                                                    |
     |                                                    | Pass 1: pricing shape
     |                                                    | (declaration order, q-values stripped)
     |                                                    |
     |                                                    v
     |                                              +-----+-----+
     |                                              | response  |
     |                                              | pipeline  |
     |                                              +-----+-----+
     |                                                    |
     |                                                    | Pass 2: transformation shape
     |                                                    | (q-value-aware; selects body transform)
     |                                                    v
                            +-----------------------------+-----------------------------+
                            |                             |                             |
                            v                             v                             v
                      boilerplate                    markup                       json_envelope
                      (strip nav,                    (HTML to                     (wrap Markdown +
                       footer, aside,                 Markdown)                    title + license +
                       comment-section)                                            tokens + JSON-LD)
                            |                             |                             |
                            +--------------+--------------+--------------+--------------+
                                           |                             |
                                           v                             v
                                     citation_block                 response headers
                                     (prepends source              Content-Signal: ai-train
                                      / license line               x-markdown-tokens: 1420
                                      when required)               Content-Type: application/json;
                                                                     profile="https://sbproxy.dev/
                                                                     schema/json-envelope/v1"

                            Projection routes (served from the same hostname):
                                /robots.txt              -> robots projection
                                /llms.txt                -> llms.txt projection
                                /llms-full.txt           -> llms-full.txt projection
                                /licenses.xml            -> RSL 1.0 projection
                                /.well-known/tdmrep.json -> W3C TDMRep projection
```

Caption: the same request produces three things. A 402 challenge that prices the request against the pricing-pass shape. A response body transformed into the transformation-pass shape. A set of four well-known documents that advertise the same license and pricing posture in machine-readable form, served at canonical URLs so cooperative crawlers can discover them without a 402 round-trip.

## Configuring content negotiation

The two-pass shape resolution is automatic for any origin that has an `ai_crawl_control` policy. The compiler synthesises an `auto_content_negotiate` action at the head of the response pipeline so neither the operator's `action:` nor `transforms:` block has to mention shape resolution explicitly.

### Auto-prepended action

When an origin declares `ai_crawl_control` with no explicit `content_negotiate` action, the compiler prepends one:

```yaml
origins:
  "blog.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        content_signal: ai-train
        tiers:
          - route_pattern: /articles/*
            content_shape: markdown
            price:
              amount_micros: 1000
              currency: USD
            citation_required: true
          - route_pattern: /articles/*
            content_shape: html
            price:
              amount_micros: 500
              currency: USD
```

There is no `content_negotiate` action in the YAML. The compiler synthesises one with `default_content_shape: html`. An incoming `Accept: text/markdown` request is resolved as Markdown on both passes; an incoming `Accept: */*` falls back to HTML; an incoming `Accept: text/html;q=1.0, text/markdown;q=0.9` is priced as HTML (declaration order) and transformed as HTML (q-value winner).

### Override with an explicit action

When the operator wants control over the wildcard default, declare a `content_negotiate` action explicitly. The compiler skips the synthesis step in that case.

```yaml
origins:
  "docs.example.com":
    action:
      type: content_negotiate
      default_content_shape: markdown
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
```

With `default_content_shape: markdown`, an `Accept: */*` request resolves to Markdown for both pricing and transformation. An agent that sends no `Accept` header at all gets the Markdown projection.

The valid values for `default_content_shape` are `html`, `markdown`, `json`, `pdf`. Absence equals `html`.

### Q-value tie-break

Pass 2 is q-value-aware. When two recognised media types tie at the same q-value, the proxy resolves them in canonical preference order: `markdown` beats `json` beats `html` beats `pdf`. This is fixed by the proxy and not configurable, because the canonical order is a transformation-capability constraint, not a pricing decision.

The pricing pass remains declaration-order first-match. Operators express pricing intent through the order of tiers in the `ai_crawl_control` policy; agents express transformation preference through q-values. The two surfaces are deliberately independent.

The full contract lives in [adr-content-negotiation-and-pricing.md](adr-content-negotiation-and-pricing.md).

### Worked examples

```bash
# Markdown shape, Markdown tier, Markdown response.
curl -i -H 'Host: blog.example.com' \
        -H 'User-Agent: GPTBot/1.0' \
        -H 'Accept: text/markdown' \
        -H 'crawler-payment: tok_a89be2f1' \
        http://localhost:8080/articles/foo
```

Expected: `200 OK`, `Content-Type: text/markdown`, body in Markdown, `Content-Signal: ai-train`, `x-markdown-tokens: <n>`.

```bash
# HTML pricing, Markdown rendering (q-value tie-break).
curl -i -H 'Host: blog.example.com' \
        -H 'User-Agent: GPTBot/1.0' \
        -H 'Accept: text/markdown;q=0.9, text/html;q=0.9' \
        -H 'crawler-payment: tok_a89be2f1' \
        http://localhost:8080/articles/foo
```

Expected: priced against the Markdown tier (declaration order picks `text/markdown` first), but the response body is Markdown because the q-value tie-break in Pass 2 prefers Markdown over HTML.

```bash
# JSON envelope shape.
curl -i -H 'Host: blog.example.com' \
        -H 'User-Agent: GPTBot/1.0' \
        -H 'Accept: application/json' \
        -H 'crawler-payment: tok_a89be2f1' \
        http://localhost:8080/articles/foo
```

Expected: `200 OK`, `Content-Type: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"`, body is the JSON envelope (see "JSON envelope shape" below).

## The four projections

The proxy serves four well-known documents on every hostname that has an `ai_crawl_control` policy. They are not static files; they are projections of the operator's compiled config. Each one regenerates atomically on every config reload, served from an in-memory cache that the data plane reads with a single atomic load. There is no separate sync process and no separate config store.

### `robots.txt`

Served at `/robots.txt`. Format follows IETF draft-koster-rep-ai (the AI-extended robots.txt).

```text
# Generated by SBproxy. Do not edit.
# Config version: 0xa3f9d2c1

User-agent: GPTBot
Disallow: /premium/*
Crawl-delay: 1
# SBproxy-AI-Extension: pay-per-crawl price=0.005 currency=USD shape=html

User-agent: *
Disallow:
```

One `User-agent:` stanza per agent class with at least one priced tier. The `# SBproxy-AI-Extension:` comment lines carry pricing metadata for cooperative crawlers; the prefix is intentionally non-standard pending IETF standardisation. Agent classes resolved from `tiers[].agent_id` selectors; `*` is the wildcard.

### `llms.txt` and `llms-full.txt`

Served at `/llms.txt` (concise) and `/llms-full.txt` (full). Format follows the Anthropic / Mistral convention: a metadata block followed by a Markdown site description.

```text
# sitename: blog.example.com
# version: 0xa3f9d2c1
# payment: pay-per-request
# shapes: html, markdown, json

# Pay-per-crawl content

This site is monetized via SBproxy. Cooperative crawlers can read the
license terms at /licenses.xml and the rights reservation at
/.well-known/tdmrep.json.
```

`llms-full.txt` adds a Markdown listing of every priced route. Both bodies regenerate at config reload time.

### `/licenses.xml`

Served at `/licenses.xml`. RSL 1.0 format. One `<license>` element per origin-level `Content-Signal` value.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">
  <license urn="urn:rsl:1.0:blog.example.com:0xa3f9d2c1">
    <origin hostname="blog.example.com" />
    <ai-use type="training" licensed="true" />
    <content-signal>ai-train</content-signal>
  </license>
</rsl>
```

The URN format is `urn:rsl:1.0:<origin_hostname>:<config_version_hash>`. The same URN appears in the `license` field of the JSON envelope so an agent that consumes the envelope and the licenses.xml document sees a consistent identifier.

The `Content-Signal` to `<ai-use>` mapping is locked by [adr-policy-graph-projections.md](adr-policy-graph-projections.md) and documented in detail in [rsl.md](rsl.md).

### `/.well-known/tdmrep.json`

Served at `/.well-known/tdmrep.json`. W3C TDMRep JSON format. One entry per priced route.

```json
{
  "version": "1.0",
  "generated": "2026-05-01T12:00:00Z",
  "policies": [
    {
      "location": "/articles/*",
      "mine-type": ["text/html", "text/markdown"],
      "right": "train",
      "license": "https://sbproxy.dev/licenses/blog.example.com"
    }
  ]
}
```

The `right` field maps `Content-Signal` values: `ai-train` produces `"right": "train"`, `ai-input` and `search` produce `"right": "research"`, an absent signal produces no entry (no right asserted equals right reserved).

### Refresh-on-config-reload semantics

The four projections live in a single `Arc<ProjectionDocs>` cache, swapped atomically on every config reload via `ArcSwap::store`. Readers pay one atomic load per request; writers pay one store per reload. There is no locking on the data path.

The reload path computes a config version hash, passes it to the projection engine, and stamps it on every regenerated document. The hot path checks the version against the live pipeline before serving so a stale cache hit is impossible in steady state.

Every projection regeneration emits one `AdminAuditEvent` per (hostname, projection kind) pair with `action: PolicyProjectionRefresh`, `target_kind: "PolicyProjection"`, and an `after.doc_hash` SHA-256 of the body. An operator with 10 origins sees 40 audit events per reload. The hash lets external auditors verify that the served document matches what was recorded at reload time.

### Operator preview via CLI

Operators preview a projection before pushing config with the `sbproxy projections render` CLI subcommand. The CLI compiles the YAML the same way the proxy boot path does, runs the projection engine on the compiled output, and writes the document to stdout.

```bash
sbproxy projections render --kind robots --config ./sb.yml
sbproxy projections render --kind llms --config ./sb.yml
sbproxy projections render --kind licenses --config ./sb.yml
sbproxy projections render --kind tdmrep --config ./sb.yml
```

The output is byte-for-byte identical to the document the proxy would serve for the same config. Use it in CI to gate config changes on the projection content.

## Per-tier `content_signal` config

`Content-Signal` is a per-route editorial declaration. Operators set it at the origin level (one value for the whole hostname) or at the tier level (overriding the origin value for matching routes).

```yaml
origins:
  "blog.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        content_signal: ai-train          # origin-level default
        tiers:
          - route_pattern: /premium/*
            content_signal: ai-input      # override: premium content licensed for inference, not training
            price:
              amount_micros: 5000
              currency: USD
          - route_pattern: /articles/*
            price:
              amount_micros: 1000
              currency: USD
```

The valid values are `ai-train`, `ai-input`, `search`. The set is closed; an unknown value rejects the config at load time with an error referencing this guide.

The matched tier's value (or the origin default when no tier matches) is stamped on `Content-Signal:` on every 200 response. A missing value means the response carries no header; existing crawlers see no change.

The `Content-Signal` header is a cooperative signal for standards-compliant crawlers and a mandatory field in the `<content-signal>` element of `/licenses.xml`. It is not security-critical; a motivated crawler can ignore it. The fact that it is asserted on the wire is what makes it actionable downstream: the JSON envelope's `license` URN and the `/licenses.xml` body together carry the operator's binding declaration of license terms.

The full contract lives in [adr-content-negotiation-and-pricing.md](adr-content-negotiation-and-pricing.md) and the policy-graph projection in [adr-policy-graph-projections.md](adr-policy-graph-projections.md).

## JSON envelope shape

When the agent sends `Accept: application/json` and the matched tier resolves to `Json` shape, the proxy wraps the page's Markdown body in a structured envelope.

```json
{
  "schema_version": "1",
  "title": "Article Title",
  "url": "https://blog.example.com/articles/foo",
  "license": "urn:rsl:1.0:blog.example.com:0xa3f9d2c1",
  "content_md": "# Article Title\n\nBody in Markdown...",
  "fetched_at": "2026-05-01T12:00:00Z",
  "citation_required": true,
  "schema_org": { "@context": "https://schema.org", "@type": "Article" },
  "token_estimate": 1420
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Currently `"1"`. String, not integer, for forward-compat. |
| `title` | string | Page title. Empty string when no title is determinable. |
| `url` | string | Canonical URL. Falls back to the request URL when the upstream sends no `Content-Location`. |
| `license` | string | RSL URN from `/licenses.xml` for this origin, or `"all-rights-reserved"` when no RSL policy is configured. Never empty. |
| `content_md` | string | Markdown body. Same content as the `text/markdown` response for the same request. |
| `fetched_at` | string | RFC 3339 timestamp at which the proxy fetched the upstream response. UTC, millisecond precision. |
| `citation_required` | bool | `true` when the matched tier sets `citation_required: true`. |
| `schema_org` | object | Pass-through of the page's first JSON-LD block. `null` or absent when the page has none. |
| `token_estimate` | integer | Approximate token count of `content_md`. Identical to the `x-markdown-tokens` response header value. |

The response is served with:

```
Content-Type: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"
```

The `profile` parameter follows RFC 6906. The URL is a stable documentation anchor; agents can branch on it to handle multiple schema versions during a dual-emit window. The profile URL is independent of the `schema_version` field; both will track together in practice but are separate fields because `schema_version` is in the body (for parsers that read the body before headers) and `profile` is in the header (for parsers that decide before parsing).

### Versioning and dual-emit

`schema_version` is a string for forward-compat with potential `"1.1"` soft additions. Adding an optional field is non-breaking and does not bump the version. Removing a field, renaming a field, or changing a field's type is breaking and bumps to `"2"`.

A v2 ships with a dual-emit window: the proxy emits both v1 and v2 envelopes depending on the agent's `Accept` profile parameter. An agent that sends `Accept: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"` receives v1; an agent that sends the v2 profile URL receives v2. After the deprecation window, the v1 profile gets `406 Not Acceptable` with an upgrade prompt.

The full schema contract lives in [adr-json-envelope-schema.md](adr-json-envelope-schema.md).

### PII redaction

The redaction middleware (in `sbproxy-security::pii`) runs over the entire serialised envelope body. The `content_md` field is the primary redaction target; `title`, `url`, `license`, and the metadata fields are proxy-generated and not subject to content redaction. `schema_org` is upstream pass-through and is redacted along with `content_md` because the operator's PII policy may not be aware of every field the upstream embeds.

This is fail-safe over precision. A future revision can add a per-origin `pii_exclude_fields` config to exempt specific JSON paths from redaction.

## Transforms

Four response-body transforms are added to the response pipeline in this order:

1. **`boilerplate`**: drops `<nav>`, `<footer>`, `<aside>`, and comment-section elements from the HTML body before any other transform sees it. Cuts token counts on typical news / blog pages by 30 to 60 percent without losing article content. Conservative selectors: only the four element types listed; no class- or id-based heuristics. Operators who want stricter stripping can add a `replace_strings` or `html` transform after `boilerplate` runs.
2. **`markup`**: HTML to Markdown via `pulldown-cmark`. Stamps `MarkdownProjection { body, title, token_estimate }` on the request context. Title is extracted from the first H1 heading in the body, falling back to the HTML `<title>` element when H1 is absent. Token estimate is computed once here using the configured `token_bytes_ratio` (default 0.25 tokens per byte for English prose) and is the only place the estimate is computed; downstream stages read it from the context.
3. **`citation_block`**: prepends a citation header to the Markdown body when the matched tier asserts `citation_required: true`. The block carries source URL, license URN, and `fetched_at` timestamp:

   ```markdown
   > Source: https://blog.example.com/articles/foo
   > License: urn:rsl:1.0:blog.example.com:0xa3f9d2c1
   > Fetched: 2026-05-01T12:00:00Z

   # Article Title

   Body...
   ```

4. **`json_envelope`**: wraps the (possibly citation-prepended) Markdown body in the JSON envelope. Runs only when the resolved transformation shape is `Json`. The serialised envelope flows through the redaction pipeline before reaching the wire.

The order is fixed in the compiled chain. Boilerplate stripping runs before HTML to Markdown so the markup transform sees the article-only DOM. Citation block runs after markup so the prepend operates on the Markdown body, not the HTML body. JSON envelope runs last so it wraps the citation-augmented Markdown.

For Markdown responses, the chain stops at step 3. For JSON envelope responses, it runs all four. For HTML pass-through, only `boilerplate` runs (and only when the operator opts in; HTML pass-through bypasses Markdown projection by default to preserve byte-for-byte fidelity).

The token estimate computed in step 2 is the same value stamped on the `x-markdown-tokens` response header and into the `token_estimate` field of the JSON envelope. The implementation contract is "compute once, share twice"; recomputing in two places would risk rounding divergence.

## Robots / llms / RSL / TDMRep cookbook

A small worked example for each of the four projections. Each shows the operator's `ai_crawl_control` config and the resulting projection body, so an operator can see how to express a specific stance and verify the output via `sbproxy projections render`.

### Recipe 1: Allow training, require attribution

```yaml
origins:
  "blog.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        content_signal: ai-train
        tiers:
          - route_pattern: /articles/*
            citation_required: true
            price:
              amount_micros: 1000
              currency: USD
```

`/licenses.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">
  <license urn="urn:rsl:1.0:blog.example.com:0xa3f9d2c1">
    <origin hostname="blog.example.com" />
    <ai-use type="training" licensed="true" />
    <content-signal>ai-train</content-signal>
  </license>
</rsl>
```

`/.well-known/tdmrep.json` carries `"right": "train"`. Markdown responses get a citation block prepended. JSON envelope responses set `citation_required: true`.

### Recipe 2: Allow inference, block training

```yaml
origins:
  "docs.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        content_signal: ai-input
        tiers:
          - route_pattern: /api-reference/*
            price:
              amount_micros: 500
              currency: USD
```

`/licenses.xml` asserts `<ai-use type="inference" licensed="true" />`. `/.well-known/tdmrep.json` carries `"right": "research"` (the W3C TDMRep value that maps to inference / RAG use). Crawlers attempting to use this content for training operate outside the licensed set; the absence of an `ai-train` declaration is the operator's signal that training is not licensed.

### Recipe 3: Block all AI use, default-deny

```yaml
origins:
  "private.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        # No content_signal: declared. The default-deny rule applies.
        crawler_user_agents:
          - GPTBot
          - ClaudeBot
          - PerplexityBot
          - CCBot
        tiers:
          - route_pattern: /*
            price:
              amount_micros: 999999999      # effectively unbuyable
              currency: USD
```

`/licenses.xml` asserts `<ai-use type="training" licensed="false" />` (the default-deny mapping). `/.well-known/tdmrep.json` emits no `policies[]` entries (the absent `Content-Signal` produces "no right asserted equals right reserved"). The high tier price on `/*` produces a 402 challenge with a price the operator does not actually expect to be paid; the policy is effectively a paywall on every AI-class request.

This is the recommended posture for content the operator does not want any AI use of.

### Recipe 4: Per-route override

A single origin where `/premium/*` is licensed for AI training at a premium and `/public/*` is freely indexable for search but not training:

```yaml
origins:
  "blog.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    policies:
      - type: ai_crawl_control
        content_signal: search                 # origin-level default
        tiers:
          - route_pattern: /premium/*
            content_signal: ai-train           # override
            price:
              amount_micros: 5000
              currency: USD
          - route_pattern: /public/*
            price:
              amount_micros: 0                 # free under the search signal
              currency: USD
```

`/premium/*` requests stamp `Content-Signal: ai-train` on the response; `/public/*` requests stamp `Content-Signal: search`. The `/licenses.xml` document carries one `<license>` element per origin-level signal value plus per-tier overrides; the `urn:rsl:1.0:blog.example.com:<hash>` URN is the same for both routes (the URN is per-origin per config-version, not per-route). Operators expressing finer-grained rights should rely on the TDMRep projection's per-route entries rather than splitting the URN.

Run `sbproxy projections render --kind licenses --config ./sb.yml` after making any of these changes to confirm the output before pushing to production.

## aipref signals

The `aipref:` request header expresses an opt-out preference at the resource level per draft-ietf-aipref-prefs. SBproxy parses it on inbound requests and surfaces the result to the scripting layer.

```text
aipref: train=no, search=yes, ai-input=yes
```

The header is a comma-separated list of `key=value` pairs. SBproxy recognises three keys: `train`, `search`, `ai-input`. Values are `yes` or `no`; unknown values default to `yes` (permissive).

### Default-permissive

Absence of a key means permissive. An agent that sends no `aipref:` header sees `request.aipref.train = true`, `request.aipref.search = true`, `request.aipref.ai_input = true` in the script context. This matches the IETF draft's "absence of a signal is not a signal" rule and lets operators write expressions like `request.aipref.train == false` without first probing for presence.

### Scripting surface

The parsed signal is exposed in every scripting engine (CEL, Lua, JavaScript, WASM) via the `request.aipref` namespace:

```yaml
policies:
  - type: cel
    expression: request.aipref.train || request.headers["x-research-license"] != ""
    deny_message: "Training use requires aipref: train=yes or a research license header."
```

The same fields are available from Lua via `request.aipref.train`, from JavaScript via `request.aipref.train`, and from WASM via the host-allowlisted `request_aipref_train()` import.

The full parser contract lives in `crates/sbproxy-modules/src/policy/aipref.rs`. Malformed input (a directive missing its `=` separator, an empty key) falls through to the default-permissive signal and emits a structured warn log; valid input is surfaced to scripts unchanged.

## Pointers

Companion documents:

- [ai-crawl-control.md](ai-crawl-control.md): the `ai_crawl_control` policy reference (tiers, free preview, paywall position). `content_signal` and `citation_required` attach to the same tier shape.
- [configuration.md](configuration.md): the full YAML reference (proxy settings, origins, transforms, policies). Look for the `content_negotiate` action and the new transform names.
- [observability.md](observability.md): the metrics, logs, and traces surface. Content-shaping metrics include `sbproxy_content_shape_served_total{origin, shape}` and `sbproxy_projection_refresh_total{origin, kind}`.
- [rsl.md](rsl.md): the RSL 1.0 cookbook for license-term expression. Pair this guide with that one when writing `content_signal` config.
- [adr-content-negotiation-and-pricing.md](adr-content-negotiation-and-pricing.md): the ADR that pins the two-pass `Accept` resolution.
- [adr-policy-graph-projections.md](adr-policy-graph-projections.md): the ADR that pins the four-projection contract and the audit-trail rule.
- [adr-json-envelope-schema.md](adr-json-envelope-schema.md): the ADR that pins the JSON envelope schema and versioning rules.
- [operator-runbook.md](operator-runbook.md): the on-call runbook, including the shape-rollout playbook and the licensing-policy-edit playbook.

External references:

- IETF draft-koster-rep-ai: https://datatracker.ietf.org/doc/draft-koster-rep-ai/
- RSL 1.0: https://rsl.ai/spec/1.0
- W3C TDMRep: https://www.w3.org/2022/tdmrep/
- IETF draft-ietf-aipref-prefs: https://datatracker.ietf.org/doc/draft-ietf-aipref-prefs/
- RFC 6906 (the `profile` parameter): https://www.rfc-editor.org/rfc/rfc6906
- RFC 9110 (the `Accept` header and q-values): https://www.rfc-editor.org/rfc/rfc9110

# ADR: JSON envelope schema for agent-facing content responses (Wave 4 / A4.2)

*Last modified: 2026-05-01*

## Status

Accepted. Wave 4 content-shaping pillar. Builds on `adr-schema-versioning.md` (A1.8, schema versioning rules and breaking-change checklist), `adr-log-schema-redaction.md` (A1.5, R1.2 redaction pipeline), `adr-content-negotiation-and-pricing.md` (G4.1, `ContentShape::Json` resolution and `token_estimate` source), and `adr-policy-graph-projections.md` (A4.1, RSL URN in the `license` field). Pinned by Wave 4 implementation tasks G4.4 (JSON envelope builder), G4.5 (`x-markdown-tokens` header), Q4.6 and Q4.7 (JSON envelope e2e and schema conformance).

## Context

When an agent sends `Accept: application/json` and receives a 200, it currently gets whatever the upstream returns with its own `Content-Type: application/json` shape, which may be an API response or an HTML page's JSON-LD blob. There is no standard structure that tells the agent: "here is the page content in a normalized form, here is its license, here is whether you must cite it, and here is how many tokens it occupies."

Wave 4 ships that structure as the JSON envelope. The envelope is the output shape for the `ContentShape::Json` branch in G4.4's content handler. It wraps the page's Markdown body (same projection as G4.3), adds citation metadata, and passes through any existing JSON-LD the page carries.

This ADR pins the schema, the versioning strategy, the redaction pipeline interaction, and the `Content-Type` parameter form.

## Decision

### Schema fields (Wave 4 / v1, locked)

```json
{
  "schema_version": "1",
  "title": "Article Title",
  "url": "https://example.com/articles/foo",
  "license": "urn:rsl:1.0:example.com:a3f9d2",
  "content_md": "# Article Title\n\nBody in Markdown...",
  "fetched_at": "2026-05-01T12:00:00Z",
  "citation_required": true,
  "schema_org": { "@context": "https://schema.org" },
  "token_estimate": 1420
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | yes | `"1"` in Wave 4. String not integer per A1.8 access-log convention (forward-compat for potential `"1.1"` soft additions). |
| `title` | string | yes | Page title extracted from `<title>` or the first H1 in the Markdown projection. Empty string is valid when no title is determinable. |
| `url` | string (URL) | yes | Canonical URL of the resource, from the request URL unless the upstream returns a `Content-Location` header. |
| `license` | string | yes | RSL URN (from A4.1's `licenses.xml` for this origin) or `"all-rights-reserved"` when no RSL policy is configured. Never empty. |
| `content_md` | string | yes | Markdown body produced by G4.3's projection. Same content as the `text/markdown` response for the same request. |
| `fetched_at` | string (RFC 3339) | yes | Timestamp at which the proxy fetched the upstream response. Millisecond precision; UTC only. |
| `citation_required` | bool | yes | `true` when the operator's `ai_crawl_control` config sets `citation_required: true` for this route; `false` otherwise. Default: `false`. |
| `schema_org` | object | no | Pass-through of the page's first `<script type="application/ld+json">` block, parsed and re-serialised as JSON. `null` or absent when no JSON-LD is present. |
| `token_estimate` | integer (u32) | yes | Approximate token count of `content_md`, using the same estimation function as the `x-markdown-tokens` response header (G4.5). Same value; both are derived from the same measurement at one point in the pipeline. |

### Versioning

Per A1.8, `schema_version` is a string. The initial value is `"1"`. The sibling Rust constant:

```rust
pub const JSON_ENVELOPE_SCHEMA_VERSION: &'static str = "1";
```

The constant lives in `sbproxy-modules::content::envelope` (the new module G4.4 creates). Every envelope serialisation stamps `schema_version: JSON_ENVELOPE_SCHEMA_VERSION`. The string form matches the access-log schema convention, which uses `"1"` (string) rather than `1` (integer) for forward-compat with potential `"1.1"` soft additions.

Agents must accept additional unknown fields in the JSON object (standard JSON forward-compatibility rule, Rule 1 of A1.8). This is a consumer-side obligation; the proxy cannot enforce it.

### `Content-Type` parameter versioning

The response is served with:

```
Content-Type: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"
```

The `profile` parameter follows the IANA-registered `application/json` extension from RFC 6906. The URL is a stable documentation anchor; it does not need to be a resolvable HTTP resource in Wave 4 (the proxy does not validate its own profile URL). If the schema major-bumps to v2, the profile URL changes to `v2`; agents can branch on the profile parameter to handle both shapes during a dual-emit window.

The profile URL is independent of `schema_version`. They will track together in practice (both increment at v2); they are separate fields because `schema_version` is in the body (for agents that read the body before headers) and the profile is in the header (for agents that check the content type before parsing the body).

### Breaking-change rule (mirror of A1.8)

The A1.8 three-rule compatibility model applies:

- **Adding an optional field** (`schema_org`, `token_estimate`) to an existing v1 response is non-breaking. No version bump. Agents that don't recognise the field skip it.
- **Removing or renaming a field** is breaking. Bumps to v2. Requires the A1.8 deprecation window: dual-emit from `N` to `N+2`, hard cut at `N+3`.
- **Changing a field's type** is breaking even for widening (e.g., `token_estimate` from `u32` to `u64`). Bumps to v2.

The checklist from A1.8 § Breaking-change checklist applies to `schema_version` bumps of the JSON envelope. G4.4's PR should include the checklist only if it introduces a breaking change; Wave 4 is the initial shape and no old version exists, so no checklist is needed for Wave 4 itself.

### When does a v2 ship vs an additive v1 change?

The deciding question is: does the change break an agent that correctly implemented the v1 schema?

| Change | Breaking? | Action |
|---|---|---|
| Add `content_html` field (optional) | No | Ship; no version bump. |
| Add `pdf_url` field (optional) | No | Ship; no version bump. |
| Rename `content_md` to `content_markdown` | Yes | Dual-emit window; bump to `"2"`. |
| Remove `schema_org` | Yes | Dual-emit window; bump to `"2"`. |
| Change `token_estimate` from `u32` to `u64` | Yes | Bump to `"2"` (type change per A1.8 Rule 3). |
| Change `license` from RSL URN to SPDX expression | Yes | Bump to `"2"` (semantic re-typing). |

The dual-emit window for `schema_version "2"`: the proxy emits both `schema_version: "1"` and `schema_version: "2"` envelopes depending on the agent's `Accept` header profile parameter. An agent that sends `Accept: application/json; profile="https://sbproxy.dev/schema/json-envelope/v1"` receives the v1 body; an agent that sends the v2 profile URL receives v2. During the dual-emit window, both are valid. After `N+3`, only the v2 profile is served; v1 gets a `406 Not Acceptable` with an upgrade prompt.

### Localization

Wave 4 does not translate `title` or `content_md`. The Markdown projection (G4.3) produces content in the upstream's language. If the agent sends `Accept-Language: fr`, the proxy passes it to the upstream but does not translate the body.

The `Accept-Language` header is forwarded to the upstream unchanged. If the upstream returns French content (because it respects `Accept-Language`), the envelope will contain French `title` and `content_md`. The proxy does not detect, validate, or annotate the language of the content in Wave 4.

A future wave may add a `language` field (e.g., `"language": "fr"`) derived from the upstream's `Content-Language` response header. That is a non-breaking additive change (Rule 1) when it ships.

### PII and redaction

The R1.2 redaction middleware (in `sbproxy-security::pii`) runs over response bodies. The JSON envelope body flows through the same redaction pipeline as the Markdown response body. The envelope is serialised by G4.4, then passed to the redaction pipeline as a byte buffer, then written to the client. The `content_md` field is the primary redaction target (it contains the page body); `title`, `url`, `license`, and the metadata fields are not subject to content redaction in Wave 4 (they are proxy-generated, not upstream-echoed, except for `title` and `schema_org`).

Concrete redaction order in the response pipeline:

1. G4.3 Markdown projection runs on the upstream body.
2. G4.4 JSON envelope builder wraps the Markdown output.
3. The serialised JSON envelope bytes are passed to `PiiRedactor::redact_bytes`.
4. The redacted bytes are written to the client.

The redaction pass operates on the serialised JSON string. A PII match that spans a JSON string boundary (e.g., an email that starts in `content_md` and ends in a later field due to JSON encoding quirks) is handled correctly by the regex-based redactor because it operates on the raw byte buffer, not on parsed JSON field values.

`schema_org` contains pass-through JSON-LD from the page. It may carry the publisher's email address or other PII if the upstream embedded it. The redaction pass covers the entire serialised envelope body, so `schema_org` fields are redacted the same as `content_md`. This is correct but may over-redact `schema_org` fields that contain legitimate structured data (e.g., a `contactPoint` email). Wave 4 accepts this trade-off: fail-safe redaction over precision. A later wave can add a `pii_exclude_fields` per-origin config to exempt specific JSON paths from redaction.

### `x-markdown-tokens` header relationship

G4.5 emits `x-markdown-tokens: <n>` on Markdown and JSON envelope responses. The value is the same `token_estimate` integer in the JSON envelope body. The proxy computes the estimate once (from the Markdown body length using a fixed tokens-per-byte ratio configured per origin, defaulting to 0.25 tokens/byte for English prose) and stamps it in both places. Agents that parse the header for early budget checks see the same value they would read from the body after parsing.

The `token_estimate` field in the envelope and the `x-markdown-tokens` header are required to be identical. G4.5's implementation must read the estimate from the same in-pipeline value as G4.4, not recompute it independently. The correct implementation is: estimate is computed once in G4.3's Markdown projection step, stored in the request context, and read by both G4.4 (body field) and G4.5 (response header).

## Consequences

- The JSON envelope schema is a new public contract. The `Content-Type: application/json; profile=...` parameter gives agents a versioned handle. The `schema_version` field inside the body gives parsers that don't check headers a fallback.
- Redaction applies to the entire serialised envelope body. This is safe and simple; `schema_org` may occasionally over-redact, but the trade-off favours safety.
- `token_estimate` must be computed once and shared; two independent computations could diverge by rounding. The implementation constraint is captured here.
- Wave 4 does not add localization or PDF transformation. These are deferred with documented non-breaking extension points (optional `language` field later).
- The breaking-change checklist from A1.8 governs future v2 evolution. The dual-emit window via `Accept` profile parameter is the correct mechanism; it avoids URL versioning (`/v2/articles/foo`) and keeps resource URLs stable.

## Alternatives considered

**Use a custom MIME type (`application/sbproxy-envelope+json`) instead of `application/json; profile=...`.** Rejected. A custom vendor MIME requires agents to explicitly support it and breaks any middleware that expects `application/json`. The profile parameter is the IANA-blessed extension mechanism for `application/json` and requires no agent-side custom MIME handling.

**Embed the Markdown body in a separate `content` field of a different type (e.g., an array of blocks).** Rejected. The `content_md` string is the simplest representation that downstream LLMs can consume directly. Block-structured representations (Notion-style, Slate.js) require a separate schema and parser on the agent side with no benefit for the Wave 4 use case.

**Add a `content_html` field alongside `content_md`.** Deferred. An agent that wants HTML should send `Accept: text/html` and get the HTML response. Including HTML in the JSON envelope doubles the body size for no gain. If a future use case requires both shapes in one response, it can be added as a non-breaking optional field.

**Run redaction only on `content_md`, not on `schema_org`.** Considered. Rejected because `schema_org` is pass-through upstream content and may carry PII that the operator has not sanitised. The safe default is to redact the whole envelope. A per-origin `pii_exclude_fields` config can carve out specific paths in a later wave.

## Open questions

1. **Title extraction from the Markdown projection.** G4.3's Markdown projection produces the `content_md` body. `title` is extracted from the first H1 heading in that body, falling back to the HTML `<title>` element if H1 is absent. The extraction logic should be in G4.3, not in G4.4, to keep the envelope builder free of HTML parsing. G4.4 receives a `MarkdownProjection { body: String, title: Option<String>, token_estimate: u32 }` struct from G4.3. This interface is implied by this ADR but not defined in it; G4.4's implementor should confirm it with G4.3's implementor before starting.
2. **~~`citation_required` config surface.~~** Closed 2026-05-02 (Wave 4 day-4 pipeline-wiring lane). The flag lives on `Tier` (per-tier so it can vary by route and shape) and is resolved into `RequestContext::citation_required` by the `ai_crawl_control` tier resolver. Both `JsonEnvelopeTransform` and `CitationBlockTransform` read from the request context; each keeps an optional `force_citation: Option<bool>` for the rare standalone case where the transform runs without an `ai_crawl_control` policy. See `AIGOVERNANCE.md` § 9 (2026-05-02 entry).
3. **Token estimation function.** The default of 0.25 tokens/byte is a rough approximation for English prose. Operators with non-English content or dense technical content may want to calibrate this. A `token_bytes_ratio: f32` per-origin config (defaulting to 0.25) would let them tune it. This is a non-breaking addition; G4.5's implementor should consider it.

## References

- `adr-schema-versioning.md` (A1.8): three-rule compatibility model, breaking-change checklist, `&'static str` constant pattern, dual-emit window.
- `adr-log-schema-redaction.md` (A1.5): R1.2 redaction pipeline that covers the envelope body.
- `adr-content-negotiation-and-pricing.md` (G4.1): `ContentShape::Json` trigger, `token_estimate` source, `Content-Signal` header.
- `adr-policy-graph-projections.md` (A4.1): RSL URN format used in `license` field.
- `crates/sbproxy-security/src/pii.rs`: `PiiRedactor::redact_bytes` pipeline.
- `crates/sbproxy-modules/src/policy/ai_crawl.rs`: `AiCrawlControlConfig`, `ContentShape::Json`.
- Wave 4 implementation tasks: G4.4 (envelope builder), G4.5 (`x-markdown-tokens` header), Q4.6, Q4.7.
- RFC 6906: `profile` link relation type (the basis for the `profile` parameter in `application/json`).
- IANA `application/json` media type registration: no `profile` parameter is formally registered, but RFC 6906 § 3 describes the convention used here.

# ADR: Content negotiation and per-shape pricing matrix

*Last modified: 2026-05-03*

## Status

Accepted. Builds on the per-shape pricing implementation in `crates/sbproxy-modules/src/policy/ai_crawl.rs` (`matched_tier_for_request` / `Tier::matches_shape`).

## Context

Per-shape pricing landed earlier (`ContentShape` enum, `Tier::matches_shape`, `matched_tier_for_request`) but treated `Accept` header parsing as advisory. The `ContentShape::from_accept` function does a first-match-wins scan, strips q-values, and stops at the first recognised MIME type. That is correct for the pricing-tier lookup, but it does not address three remaining requirements:

1. The proxy now must actually transform the response body into the negotiated shape (HTML to Markdown, any shape to JSON envelope). The shape resolved at pricing time must be the same shape the transformer sees.
2. The `Content-Signal` header adds a per-route editorial signal (`ai-train`, `search`, `ai-input`) that downstream license projections and RSL terms reference.
3. The interaction between content-shape binding in quote tokens and the new JSON envelope shape (`application/json`) must be pinned so quote-token verifiers do not accept cross-shape redemptions.

The existing `Accept-Payment` negotiation solves rail preference ordering with q-values. This ADR solves shape preference ordering by the same mechanism, documents the tie-break rule when q-values produce ambiguity, and pins the failure mode for the wildcard `Accept: */*`.

## Decision

### Accept header matrix

The MIME types the proxy recognises for content negotiation, in canonical preference order when the operator has not configured a per-route default:

| MIME type(s) | `ContentShape` | Notes |
|---|---|---|
| `text/markdown`, `text/x-markdown` | `Markdown` | LLM-native; produces Markdown projection. |
| `application/json`, `application/ld+json` | `Json` | Produces JSON envelope. |
| `text/html`, `application/xhtml+xml` | `Html` | Pass-through (no body transformation). |
| `application/pdf` | `Pdf` | Pass-through. |
| `*/*` (or absent) | default | See wildcard rule below. |

This is not a new enum; it is the existing `ContentShape` from `crates/sbproxy-modules/src/policy/ai_crawl.rs`. The content handler reads the same value from the resolved tier to drive the response transformer, closing the loop between pricing and transformation.

### Q-value tie-break rule

When an agent sends a compound `Accept` header with q-values, the proxy resolves the shape using a two-pass algorithm:

**Pass 1 (price lookup).** `ContentShape::from_accept` is called unchanged. It strips q-values and returns the first recognised MIME in declaration order. This is the price-resolution shape; the result is passed to `matched_tier_for_request` to select the tier and amount. This pass does not change.

**Pass 2 (response transformation).** A separate q-value-aware resolver scans the `Accept` header, collects all recognised MIME types with their q-values, and selects the one with the highest q-value. If two types share the same q-value, the one with the lower priority rank in the canonical preference order above wins (Markdown before Json before Html, on the assumption that LLM-native formats are preferable).

The two passes are separate because the price-resolution semantics (first-match-wins per the existing tier-ordering contract) must not change. The response-transformation semantics introduce q-value awareness only in the transformer selection, not in the pricing.

**Worked example.** Agent sends `Accept: text/html;q=1.0, text/markdown;q=0.9`.

- Pass 1: first recognised MIME is `text/html`. Price resolves against the `Html` tier (if one exists) or the path-only catch-all.
- Pass 2: q-value-aware scan finds `text/html` (q=1.0) beats `text/markdown` (q=0.9). Transformer: HTML pass-through.
- Outcome: tier price is the HTML tier price; response body is untransformed HTML. `Content-Signal` is stamped per the route config.

**Worked example.** Agent sends `Accept: text/markdown;q=0.9, text/html;q=0.9` (tie).

- Pass 1: first recognised MIME is `text/markdown`. Price resolves against the Markdown tier.
- Pass 2: tie at q=0.9. Canonical preference order: Markdown (rank 1) beats Html (rank 3). Transformer: Markdown projection.
- Outcome: Markdown tier price; response is Markdown-projected. The agent declared equal preference; the proxy resolves in the canonical order.

This is a deliberate divergence from `Accept-Payment` tie-break (in `adr-multi-rail-402-challenge.md`), which uses the operator's preference order (not a canonical order). The content-shape canonical order is fixed by this ADR, not by per-route config, because transformation is a proxy capability constraint, not an operator pricing choice.

### `matched_tier_for_request` with multiple shapes

`matched_tier_for_request(path, agent_id, accept)` is called with the raw `Accept` header string. It invokes `Tier::matches_shape(accept)` on each tier in declaration order. `matches_shape` calls `ContentShape::from_accept`, which does first-match-wins on the comma-separated MIME list (q-values stripped).

This is first-match-wins-per-tier, which is the correct behaviour: the operator places more-specific tiers (shape + route) before catch-all tiers (route-only). The first tier that satisfies all three selectors (path, agent, shape) wins. There is no ambiguity across tiers.

The q-value issue is only a tie-break concern within a single MIME list on the `Accept` header. Since `from_accept` already takes the first recognised MIME, an agent that sends `text/markdown;q=0.9, text/html;q=1.0` will have its `Accept` resolved to `Markdown` for price lookup (first recognised MIME is Markdown), but the response transformer will see `Html` as the q-value winner and serve HTML. This is an intentional asymmetry: the pricing follows the declaration order (operator-influenced via tier ordering), while the transformation follows q-value intent (agent-controlled). The net result is that agents who want to pay the Markdown price but receive HTML should send `text/html` first in their `Accept` header. This is documented in the operator-facing content negotiation guide (G4.2 task).

This ADR does not close that gap. It is acceptable because the price difference between HTML and Markdown tiers is an operator choice, and the agent's q-values express rendering preference, not price preference. A future revision can add a strict mode that matches the transformation shape to the pricing shape if operators request it.

### `Content-Signal` response header

When the origin's `ai_crawl_control` policy (or the new `content_signal` config key at the origin level) sets a signal value, the proxy stamps `Content-Signal: <value>` on 200 responses. The closed set of values:

| Value | Semantics |
|---|---|
| `ai-train` | Content is licensed for AI training (per operator's RSL terms). |
| `search` | Content may be indexed for search but not used for training. |
| `ai-input` | Content may be used as model input (inference) but not for training. |

The value is per-route. Operators set it in the `ai_crawl_control` tier or at the origin level. A missing `Content-Signal` header means no signal is asserted; existing crawlers see no change.

The header is a read surface for RSL's per-inference license terms (the RSL trust model says: "if the gateway asserts `ai-input`, the ingesting model must have a valid RSL inference license"). `adr-policy-graph-projections.md` covers how the policy-graph projection maps these values into `licenses.xml` and `tdmrep.json`. This ADR only pins the header name and value vocabulary.

The `Content-Signal` header is not security-critical; a motivated crawler can ignore it. It is a cooperative signal for standards-compliant crawlers and a mandatory field in the JSON envelope.

### Interaction with quote tokens

A quote token issued for shape `html` contains `"shape": "html"` in its payload claims (`adr-quote-token-jws.md`). The quote-token verifier (in `crates/sbproxy-modules/src/policy/quote_token.rs`) checks the `shape` claim against the incoming request's resolved content shape. A token issued for `html` is not redeemable against a `markdown` request.

The shape the verifier checks against is the Pass 1 (pricing) shape, not the Pass 2 (transformation) shape. The pricing shape is the one that was offered when the token was minted. The verifier confirms that the shape in the token is the `ContentShape::as_str()` value from the tier that was matched when the 402 was issued.

Cross-shape redemption is a server-side programming error detectable in the audit trail: the audit event carries both the token's `shape` claim and the request's resolved shape. When they diverge, the ledger logs a `shape_mismatch` error code and rejects the token with a hard `LedgerError`.

### Wildcard `Accept: */*` default shape

When an agent sends `Accept: */*` or no `Accept` header, `ContentShape::from_accept` returns `None`. The tier matcher then skips all shape-specific tiers and matches only tiers with `content_shape = None`. The response transformer sees no shape preference and serves the origin's native format (typically HTML for web origins).

The default shape per origin is `Html`. This matches current behaviour: the upstream returns its own content type; the proxy passes it through. The operator can override the default shape at the origin level via a `default_content_shape` field, which must be one of `html`, `markdown`, or `json`. When set, `Accept: */*` resolves to the configured default.

The `default_content_shape` field is optional. Its absence means `Html`. This is a non-breaking additive change under the schema-versioning rules.

### Worked examples

**Example 1: Agent requests Markdown, operator has a Markdown tier.**

```
GET /articles/foo HTTP/1.1
Accept: text/markdown
Accept-Payment: x402;q=1, mpp;q=0.9
X-X402-Version: 2
```

- `matched_tier_for_request("/articles/foo", "", "text/markdown")` finds the Markdown tier, price 1000 micros.
- Multi-rail 402 body emitted with `amount_micros: 1000` in both entries.
- Quote token: `"shape": "markdown"`.
- On retry with valid token: proxy confirms shape match, upstream response is Markdown-projected.
- Response includes `Content-Signal: ai-input` (per route config) and `Content-Type: text/markdown`.

**Example 2: Agent sends mixed Accept with q-value tie, no Markdown tier.**

```
GET /articles/foo HTTP/1.1
Accept: text/markdown;q=0.9, text/html;q=0.9
```

- Pass 1: `from_accept` returns `Markdown` (first recognised MIME).
- Tier lookup: no Markdown-specific tier, falls through to path-only catch-all. Price from catch-all tier.
- Quote token: `"shape": "markdown"` (from the pricing pass).
- On 200: Pass 2 tie-break resolves to Markdown (rank 1 beats Html rank 3). Response is Markdown-projected.

**Example 3: Agent sends `Accept: */*`, no `default_content_shape` configured.**

- Shape: `None`. Tier lookup finds path-only catch-all.
- Transformer: no transformation. Upstream HTML passed through.
- `Content-Signal` stamped if configured at origin level.
- Quote token: `"shape": "html"` (the effective default).

## Consequences

- The two-pass shape resolution is a small amount of extra logic in the content handler, but it keeps the pricing semantics (first-match-wins tier order) unchanged and adds q-value awareness only in the transformer path. No existing tiers or policies change behaviour.
- The `Content-Signal` header is a new response header. It is opt-in per origin config. Existing clients that do not look for it are unaffected.
- The wildcard default of `Html` is safe and matches current behavior. Operators who want Markdown-first must set `default_content_shape: markdown` explicitly.
- The cross-shape redemption hard-reject is the correct fail-closed behavior. An agent that acquires a Markdown token and tries to redeem it against an HTML request is either misconfigured or adversarial; both cases should fail.
- Strict mode (enforcing that transformation shape matches pricing shape) is deferred. The open question below captures this.

## Alternatives considered

**Use q-values in Pass 1 (pricing) as well.** Rejected. The existing tier-ordering contract (`matched_tier_for_request` returns the first matching tier) is the operator's way to express pricing preference. Injecting q-values into tier selection would break operators who deliberately place shape-specific tiers first.

**Single-pass resolution using q-values throughout.** Considered and rejected for the same reason. Pricing semantics and transformation semantics have different authority: the operator controls pricing via tier ordering; the agent controls transformation via q-values.

**Ignore q-values entirely and use declaration order for both passes.** Rejected because agents that follow RFC 9110 will declare their true preference via q-values; ignoring them means the transformer ignores the agent's stated preference.

**Add a third MIME type for per-shape 402 opt-in (e.g., `application/sbproxy-markdown+json`).** Rejected. The multi-rail 402 body already carries a `shape` field implicitly via the quote token. A per-shape MIME creates a second opt-in surface with no additional information.

## Open questions

1. **Strict mode.** Should there be a per-origin `strict_shape_match: true` flag that enforces that the transformer shape equals the pricing shape? The current behavior (they can diverge under q-value tie-breaks) is permissive. If operators report confusion about a Markdown-priced but HTML-served response, strict mode is the fix. Document in the decisions log post-merge if this comes up.
2. **PDF transformation.** `ContentShape::Pdf` passes through today. A future revision may add a PDF-to-Markdown extractor. When that lands, a `Pdf`-tier agent who receives a Markdown response needs to be handled; the strict-mode question above applies there too.

## References

- `adr-multi-rail-402-challenge.md`: `Accept-Payment` header negotiation, first-match-wins rail policy.
- `adr-quote-token-jws.md`: quote token `shape` claim and verifier cross-shape rejection.
- `adr-schema-versioning.md`: closed-enum rules for `Content-Signal` value set.
- `crates/sbproxy-modules/src/policy/ai_crawl.rs`: `ContentShape`, `Tier::matches_shape`, `matched_tier_for_request`, `ContentShape::from_accept`.
- RFC 9110 § 12.4.2: q-value syntax and preference semantics for `Accept` headers.
- RSL 1.0 license terms: https://rsl.ai/spec/1.0.

# ADR: Single-rail HTTP 402 challenge format

*Last modified: 2026-05-03*

## Status

Accepted. Builds on `adr-http-ledger-protocol.md`, `adr-schema-versioning.md`, and the existing `ai_crawl_control` policy documented in `ai-crawl-control.md`.

## Context

`ai_crawl_control` issues HTTP 402 challenges to AI crawlers that arrive without a valid `Crawler-Payment` token. The challenge tells the crawler what it costs to read the resource, what currency, and which header to use on retry. After paying out-of-band the crawler retries with the issued token; the proxy redeems the token through the ledger and either passes the request through or denies it.

The OSS distribution targets one canonical 402 shape: a single response header plus a small JSON body that names a single payment target. The shape is deliberately narrow. It is enough to wire the policy to a self-hosted ledger, an in-memory token list, or a custom rail behind a small adapter. Multi-rail negotiation between several payment rails on one response is out of scope for the OSS distribution.

## Decision

### Single-rail 402 body

When the policy denies a request that lacks a valid token, the proxy responds:

```http
HTTP/1.1 402 Payment Required
Crawler-Payment: realm="ai-crawl" currency="USD" price="0.001"
Content-Type: application/json
```

```json
{
  "error": "payment_required",
  "price": "0.001",
  "currency": "USD",
  "target": "blog.example.com/article",
  "header": "crawler-payment"
}
```

| Field | Type | Notes |
|---|---|---|
| `error` | string | Always `"payment_required"`. Distinguishes a 402 challenge from other 4xx responses with a JSON body. |
| `price` | string | Decimal price the crawler must pay. Matches the `price=` parameter in the response header. |
| `currency` | string | ISO 4217 code. Same value across the header and the body. |
| `target` | string | The host plus path the crawler is being charged for. |
| `header` | string | The header name the crawler should write its token to on retry. Defaults to `crawler-payment`. |

The body is served with `Content-Type: application/json`. The header is `Crawler-Payment` (the canonical challenge name). Both the body and the header are stable across releases; `adr-schema-versioning.md` Rule 1 governs additive evolution.

### Tier resolution before challenge emission

The price the policy emits is the price for the tier that matches the request. The matcher compares the request path against each tier's `route_pattern` and the resolved agent class against each tier's optional `agent_id`. The first tier that matches wins. When no tier matches, the policy falls back to the top-level `price` and `currency`.

Per-shape pricing is advisory in the OSS distribution: the tier may carry a `content_shape` value, which the policy surfaces in metrics and the redeem payload but does not yet use as a filter. The wire format keeps the field reserved so configurations stay forward-compatible.

### Retry path

The crawler reads the challenge, pays out-of-band, and retries the original request with the issued token in the configured header (default `Crawler-Payment`). The proxy passes the token to the configured ledger:

- The in-memory ledger (`valid_tokens:` in `sb.yml`) treats every entry as a single-use redemption; the token leaves the set on first redeem.
- The HTTP ledger client speaks the JSON-over-HTTPS protocol pinned in `adr-http-ledger-protocol.md`. The redeem call carries the token, the host, the path, the resolved price in micros, the currency, and the resolved content shape.

A redeem that returns `redeemed: true` lets the request through. A redeem that returns `redeemed: false`, a `token_already_spent` error, or any other ledger denial collapses to another 402 with a fresh challenge body.

### Backwards compatibility

The single-rail format is the only format the OSS proxy emits. There is no negotiation header for opting into a richer format. Agents that send `Accept: application/json` or no `Accept` header at all see the same body. Agents that send something else still receive the JSON body; HTTP content negotiation is not used to alter the challenge shape.

Adding optional fields to the body (e.g. `expires_at`, `documentation_url`) is non-breaking under `adr-schema-versioning.md` Rule 1. Removing or renaming a field is breaking and requires the deprecation window from that ADR.

### Multi-rail negotiation

Out of scope for the OSS distribution. Operators who need to advertise multiple payment rails on a single 402 response, with q-value preference negotiation, MIME-type opt-in, or per-rail token issuance, run that pattern outside the OSS proxy. The single-rail shape covers self-hosted ledger deployments, in-memory token issuance, and custom-rail adapters that fit behind one endpoint.

## Consequences

- One response shape across every OSS deployment. Crawlers that handle one configuration handle every configuration.
- Tier resolution stays a per-request match; price changes land via config reload without a protocol change.
- The redeem path stays a single ledger call per retry. There is no rail picker, no preference header parser, no per-rail nonce table.
- Adding optional body fields evolves the format without a version bump per `adr-schema-versioning.md` Rule 1.

## Alternatives considered

**Use HTTP content negotiation (`Accept: application/x402+json`) to pick one of several payment shapes.** Rejected for the OSS distribution. A single shape is enough for self-hosted ledgers and the OSS test surface; conditional emission adds parser branches operators do not need.

**Embed the token issuance URL in the challenge body so the crawler can pay inline.** Considered. Rejected because the OSS distribution does not run a payment server; the body's `target` is descriptive, not a payment endpoint. Operators with their own payment server document the URL out-of-band.

**Stuff the price plus the rail name plus the facilitator URL into one comma-delimited header.** Rejected. The header is already comma-delimited for `realm`, `currency`, and `price`; nesting more parameters confuses parsers. The body is the safer carrier for any extension data.

## References

- `adr-http-ledger-protocol.md`: the wire protocol the redeem path speaks.
- `adr-schema-versioning.md`: the additive-evolution rule for the body schema.
- `ai-crawl-control.md`: the policy that issues these challenges and the configuration shape.

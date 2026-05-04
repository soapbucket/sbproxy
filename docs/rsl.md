# RSL 1.0 licensing cookbook

*Last modified: 2026-05-01*

This is the cookbook for expressing a specific license stance via SBproxy YAML and seeing the result in the `/licenses.xml` document the proxy serves. The reader is a publisher author or counsel who wants the right RSL terms on the wire without writing XML by hand.

If you have not yet wired `ai_crawl_control` on the origin, read [ai-crawl-control.md](ai-crawl-control.md) first. If you want the broader picture (content negotiation, JSON envelope, the four projections, transforms), read [content-for-agents.md](content-for-agents.md).

## What RSL 1.0 expresses

The Really Simple Licensing 1.0 specification (RSL Collective, December 2025, https://rsl.ai/spec/1.0) is a machine-readable XML document that asserts the license terms a publisher offers for AI ingestion of their content. It addresses three categories of AI use:

- **Training (`type="training"`).** Whether the content may be used as training data for a model. Pay-per-crawl pricing typically attaches here.
- **Inference (`type="inference"`).** Whether the content may be used as model input at inference time, e.g. as RAG context or as a tool-use payload. Pay-per-inference pricing attaches here.
- **Search indexing (`type="search-index"`).** Whether the content may be indexed for a non-LLM search engine. Often free or nominally priced.

Each category carries a `licensed="true"` or `licensed="false"` attribute. The default RSL stance is fail-closed: a category that is not asserted is unlicensed. SBproxy's `ai_crawl_control` policy maps to the RSL 1.0 vocabulary directly, so the operator's YAML is the source of truth for the served `/licenses.xml`.

RSL is cooperative, not enforceable on its own. A motivated agent that ignores the document still gets a 402 challenge from the proxy if it tries to access a priced route. RSL exists so cooperative agents (the ones that pay) and licensing counterparties (News Corp, Meta, content licensing aggregators) have a stable, machine-readable artifact to reference.

## The mapping

The operator declares the editorial signal via `content_signal:` at the origin level or inside an individual tier. The proxy translates the signal into the matching `<ai-use>` assertion when it renders `/licenses.xml`. The mapping table is locked by [adr-policy-graph-projections.md](adr-policy-graph-projections.md) (A4.1):

| `content_signal` value | RSL `<ai-use>` element |
|---|---|
| `ai-train` | `<ai-use type="training" licensed="true" />` |
| `ai-input` | `<ai-use type="inference" licensed="true" />` |
| `search` | `<ai-use type="search-index" licensed="true" />` |
| absent | `<ai-use type="training" licensed="false" />` |

The "absent" row is the default-deny rule. When an operator configures `ai_crawl_control` without setting `content_signal`, the proxy emits an explicit `licensed="false"` for training. Cooperative agents that read the document see that the operator has not licensed training; they should not use the content for that purpose.

The set of `content_signal` values is closed. The proxy rejects any other value at config-load time with a clear error message referencing this document. Future expansion (e.g., a `derivative-allowed` axis) follows the A1.8 schema-versioning rules: additive only, dual-emit window for breaking changes.

## Worked recipes

Each recipe shows the operator's `ai_crawl_control` policy, the resulting `/licenses.xml` body, and a short explanation. Run `sbproxy projections render --kind licenses --config ./sb.yml` against your config to confirm the output matches before pushing to production.

### Recipe 1: Allow training, require attribution

The operator licenses training but wants every downstream model output that uses the content to cite the source. Pricing is per-crawl on `/articles/*`.

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

The `citation_required: true` flag does not appear in the RSL document directly. It propagates to the JSON envelope (`citation_required: true`) and to the citation_block transform (which prepends a `> Source: ... > License: ...` block to the Markdown body). RSL captures the licensing posture; the citation requirement rides on the response body and the per-tier `Tier::citation_required` field.

### Recipe 2: Allow inference, block training

The operator wants their reference content available to RAG pipelines but not to training jobs. Pricing is per-inference on `/api-reference/*`.

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

`/licenses.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">
  <license urn="urn:rsl:1.0:docs.example.com:0xb1c2d3e4">
    <origin hostname="docs.example.com" />
    <ai-use type="inference" licensed="true" />
    <content-signal>ai-input</content-signal>
  </license>
</rsl>
```

The document asserts `<ai-use type="inference" licensed="true" />`. There is no assertion about training, which under the RSL fail-closed rule means training is not licensed. Cooperative training-job operators that read the document should not include this origin's content in their training set. An inference-time RAG pipeline that pays the per-inference price and presents the content as model input is operating inside the licensed set.

### Recipe 3: Block all AI use, default-deny

The operator does not want any AI use of the origin's content. Pricing is intentionally prohibitive on `/*`; the policy is effectively a paywall.

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
              amount_micros: 999999999
              currency: USD
```

`/licenses.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rsl.ai/spec/1.0" version="1.0">
  <license urn="urn:rsl:1.0:private.example.com:0x7e8f9a0b">
    <origin hostname="private.example.com" />
    <ai-use type="training" licensed="false" />
  </license>
</rsl>
```

The absence of `content_signal` triggers the default-deny mapping: `<ai-use type="training" licensed="false" />`. This is the explicit form of "the operator has not granted permission". The policy is also defensive on the wire: the high tier price ensures that any AI-class user agent that ignores the RSL stance still hits a 402 with an unbuyable price. The runbook playbook for incidents involving prohibited AI use against this origin lives in [operator-runbook.md](operator-runbook.md).

### Recipe 4: Per-route override

The operator wants their reference content (`/api-reference/*`) freely indexable for search but their premium articles (`/premium/*`) licensed for AI training at a premium price. The origin-level default is `search`; one tier overrides to `ai-train`.

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
          - route_pattern: /api-reference/*
            price:
              amount_micros: 0                 # free under search signal
              currency: USD
```

The `/licenses.xml` document asserts the origin-level signal (`search`) plus a per-tier override row when `content_signal` is set on a tier. The Wave 4 schema emits one `<license>` element per origin; a future revision may emit a `<route>` child for per-tier overrides. For the current schema, the policy posture per route is most accurately observed via `/.well-known/tdmrep.json`, which does emit per-route entries.

A runtime request to `/premium/foo` produces `Content-Signal: ai-train` on the response. A request to `/api-reference/v1` produces `Content-Signal: search`. The `urn:rsl:1.0:blog.example.com:<hash>` is the same for both routes because the URN is per-origin per config-version, not per-route.

For finer-grained per-route license expression, lean on the `/.well-known/tdmrep.json` projection or split the routes onto separate hostnames (one origin per license posture).

## URN format

The RSL URN format SBproxy emits is:

```
urn:rsl:1.0:<origin_hostname>:<config_version_hash>
```

- The `1.0` segment is the RSL spec major version. The proxy re-emits the URN unchanged on every config reload until the spec major-bumps.
- `<origin_hostname>` is the bare hostname from the origin's `origins:` key. No port, no scheme, no path.
- `<config_version_hash>` is the same 64-bit hash the proxy uses internally to gate hot-reload (`u64`, lowercase hex with the `0x` prefix when emitted in human-readable form). The hash changes on every successful config reload, even when the config content is identical at the byte level: the hash includes the load timestamp so independent reloads produce distinct URNs.

The URN is the value the JSON envelope's `license` field carries on every response. It is also the value the operator references in external licensing artifacts (e.g., a News Corp licensing contract may pin a specific URN as the binding artifact for the agreement period). Counterparties can dereference the URN against the served `/licenses.xml` to prove that the operator's published terms match the contracted terms at a given point in time.

The URN does not need to be publicly resolvable as an HTTP URL. It is a stable identifier; the proxy stamps it on response bodies and headers but does not register it with any external resolver. Counterparties resolve it indirectly by fetching `/licenses.xml` from the same hostname and reading the `<license urn="...">` attribute.

## Validation

The RSL 1.0 specification publishes an XML Schema Definition (XSD) for the document shape. Operators can validate the served `/licenses.xml` against the XSD via any XML-aware tool.

```bash
# Fetch the document via curl.
curl -s -H 'Host: blog.example.com' http://localhost:8080/licenses.xml > licenses.xml

# Validate against the RSL 1.0 XSD.
xmllint --schema rsl-1.0.xsd --noout licenses.xml
# Expected: licenses.xml validates
```

The vendored XSD will land in `e2e/fixtures/rsl-1.0.xsd` as part of the Wave 5 schema-vendoring lane (the Wave 4 e2e suite pins the validation behind a feature gate; see [adr-policy-graph-projections.md](adr-policy-graph-projections.md) open question 2 for the spec-namespace tracking note). Until then, fetch the XSD directly from the RSL Collective at https://rsl.ai/spec/1.0/rsl.xsd.

A failed validation is an operator-action signal: it means the served document does not conform to the spec the proxy claims to emit. Open an issue against the SBproxy repo with the served body and the XSD validation error attached.

The same validation runs in CI: the projection-engine snapshot tests assert byte-for-byte equality against fixture documents that were validated against the XSD at commit time. Any change to the projection emitter that breaks RSL 1.0 conformance fails the CI gate.

## Companion documents

- [content-for-agents.md](content-for-agents.md): the broader Wave 4 user guide. Covers content negotiation, transforms, the JSON envelope, the other three projections (robots.txt, llms.txt, tdmrep.json), and aipref signals.
- [ai-crawl-control.md](ai-crawl-control.md): the `ai_crawl_control` policy reference. The `content_signal` field is documented inline.
- [adr-policy-graph-projections.md](adr-policy-graph-projections.md): the ADR that pins the projection contract and the `content_signal` to RSL `<ai-use>` mapping.
- [operator-runbook.md](operator-runbook.md): the on-call runbook. The Wave 4 section adds a licensing-policy-edit playbook covering safe rollout of `content_signal` changes.

External references:

- RSL 1.0 specification: https://rsl.ai/spec/1.0
- RSL 1.0 XSD: https://rsl.ai/spec/1.0/rsl.xsd
- RSL Collective: https://rsl.ai/

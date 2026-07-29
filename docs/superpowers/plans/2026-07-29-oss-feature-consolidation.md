# OSS feature consolidation delivery index

*Last modified: 2026-07-29*

This index turns the approved
[OSS feature consolidation design](../specs/2026-07-29-oss-feature-consolidation-design.md)
into a reviewable pull request series. Each runtime pull request must work on
its own. The final documentation pull request describes only behavior already
merged into `sbproxy`.

## Product rule

SBproxy is one Apache-2.0 project. "Enterprise AI Gateway" describes the API,
MCP and agent, and AI model traffic it handles. It is not a separate edition.
No current feature, page, example, or configuration field may point readers to
`sbproxy-enterprise` or `sbproxy.dev/enterprise`.

The old Go implementation is historical. Keep a reference only where migration
or compatibility context requires it, and point that reference to
<https://github.com/soapbucket/sbproxy-go>.

## Pull request sequence

| Order | Pull request | Working result | Implementation plan |
| --- | --- | --- | --- |
| 1 | Product truth, outbound HTTP, and guardrails | The OSS request path can call every documented guardrail provider through a bounded, tested client. Stale edition and hook names are gone. | [PR 1 plan](2026-07-29-oss-product-truth-guardrails.md) |
| 2 | RAG runtime | Route-scoped retrieval works through supported embedding and vector-store adapters, then returns to the normal guardrail, budget, routing, streaming, usage, and audit path. | `2026-07-29-oss-rag-runtime.md` |
| 3 | Distributed semantic cache | The canonical cache can use memory, Redis, or the current OSS mesh without crossing tenant, credential, model, policy, or request-context boundaries. | `2026-07-29-oss-distributed-semantic-cache.md` |
| 4 | Payment settlement | Durable intents settle through Stripe, x402, MPP, CLN, or LND without performing ordinary provider calls on the proxy hot path. | `2026-07-29-oss-payment-settlement.md` |
| 5 | Documentation and examples | Concise reader paths, four tested walkthroughs, accurate configuration guidance, validated snippets, and refreshed VHS assets replace the current duplicate estate. | `2026-07-29-documentation-consolidation.md` |
| 6 | Website | The separate site repository removes `/enterprise`, reflects the OSS feature set, and links to the consolidated documentation. | `www.sbproxy.dev/docs/superpowers/plans/2026-07-29-oss-site-product-truth.md` |

## Merge gates for every runtime pull request

- New behavior is opt-in and existing configurations keep their behavior.
- Provider calls have deterministic local contract tests. Live credentials are
  supplemental and never replace those tests.
- Configured but unavailable providers fail during load, not on the first user
  request.
- No credential, private prompt, retrieved chunk, payment proof, or signing
  material appears in logs, fixtures, recordings, or commits.
- Changed crates pass formatting, targeted Clippy, focused tests, configuration
  schema checks, and affected example construction.
- Each pull request includes the narrow reference and runnable example needed
  to operate its feature.
- Source copied from the historical private repository passes the provenance
  rules in the approved design. Unclear code is reimplemented.

## Final documentation gates

- The root README and documentation index lead with one gateway for API, MCP
  and agent, and AI model traffic.
- `getting-started.md`, `concepts.md`, and the four traffic hubs give new users
  one clear route through the product.
- Each public YAML block is validated, sourced from a validated example, or
  clearly labeled as a partial fragment.
- The four golden walkthroughs run against local deterministic fixtures and
  include request, response, log, metric, failure, and cleanup checks.
- Links, anchors, generated indexes, schema files, example configs, smoke tests,
  and VHS tapes are green.
- The personal-voice review scores each rewritten hub at 15 out of 100 or lower
  and removes em dashes, en dashes, filler, and repetitive template language.


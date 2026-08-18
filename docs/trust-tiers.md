# Trust tiers
*Last modified: 2026-08-18*

A single request can pick up identity evidence from several independent sources at once: TLS fingerprint signals, named-agent rule packs, a Web Bot Auth signature, a CAP token, a KYA identity. Each source answers its own narrow question, which leaves every downstream consumer with a fan-out problem: a rate limiter that wants to be looser for verified agents would have to inspect each verifier separately, and an audit tag that wants to record "this was a trusted, named call" would replicate the same logic again.

The trust tier collapses that fan-out into one conservative, four-value answer, computed once per request after identity enrichment and authentication have both run. Downstream code asks one question instead of several.

## The four tiers

| Tier | Meaning | What earns it |
|---|---|---|
| `suspicious` | Something actively denied this request's identity claim. | Any verifier denial: a signature that failed to verify, an expired or mismatched CAP token, an expired or revoked KYA identity, a named-agent rule that matched in a deny stance, or a high-confidence headless indicator on a TLS fingerprint the gateway trusts. |
| `strong` | A cryptographic verifier confirmed the identity. | A Web Bot Auth signature, a verified CAP token, or a verified KYA identity. A Bot Auth signature that covers the body stays provisional until the body digest verifies; a request that ends before that proof completes does not keep `strong`. |
| `named` | Recognized but not proven. | An unsigned rule pack matched a named agent (a known user-agent or fingerprint pattern) and the detection scorer agreed with at least 50 of 100 confidence. Nothing here is cryptographically bound. |
| `anonymous` | The catch-all default. | No signature, no rule-pack hit (or one with too low a score), no deny signal. |

## The ordering is the point

`suspicious` beats `strong` beats `named` beats `anonymous`, and the deny check runs first on purpose. A request carrying both a valid signature and a deny signal, say a client whose Web Bot Auth signature verifies but whose CAP token is expired, surfaces as `suspicious`, not `strong`: the operator wants to see the denial, not the contradicting valid signature. The combiner is deliberately conservative in the other direction too; missing evidence reads as neutral, never as trust.

One nuance on the deny signal, for authors of custom auth logic in [extension bundles](extension-bundles.md): a header-bearing denial is scored by its declared kind. A `challenge` (the "no credentials presented, here is how to get some" case) is neutral and does not raise the tier to `suspicious`; an `invalid_proof` (a presented credential failed) does. Mark rejected credentials `invalid_proof` even when the response also carries a `WWW-Authenticate` header, so a brute-force attempt stays visible to trust scoring.

## Consuming it

**In policy.** The tier is a CEL binding, `request.trust_tier`, with the same vocabulary in Rego as `input.request.trust_tier`:

```yaml
policies:
  - type: expression
    expression: >
      request.trust_tier == "strong" || request.trust_tier == "named"
      || !request.path.startsWith("/agent-api/")
```

It is available to the policy-phase engines (`expression`, `rego`), which run after the passes that produce it, and deliberately not to earlier sites like routing conditions; [scripting.md](scripting.md#32-what-each-config-site-offers) has the site-by-site availability table. For a routing decision that wants the tier, gate with an `expression` policy instead of a forward-rule matcher.

**On dashboards.** Every request lands one observation on `sbproxy_trust_tier_requests_total{tier}`, a closed four-value label set. A sudden shift from `anonymous` toward `suspicious` is the operational signal the tier exists to produce; per-verifier metrics then tell you which source moved.

## What it is not

- **Not an enforcement action.** The tier never blocks anything by itself; it is an input to the policies you write. A `suspicious` request with no policy reading the tier proceeds like any other.
- **Not a score.** The detection scorer's 0-100 confidence feeds the combiner (the `named` threshold is 50), but what comes out is one of four words. If you need the raw signals, the per-source bindings under `request.agent.*` still exist; see [headless-detection.md](headless-detection.md) for those.
- **Not configurable.** There is no knob to redefine the mapping. The value of a shared vocabulary is that `strong` means the same thing on every origin, every dashboard, and every audit record.

## See also

- [getting-started-agent-identity.md](getting-started-agent-identity.md) - the walkthrough that sets up the verifiers this page combines.
- [web-bot-auth.md](web-bot-auth.md), [cap.md](cap.md) - two of the signature verifiers that produce `strong`.
- [agent-budget.md](agent-budget.md) - rate limiting keyed on the resolved agent identity the tier is derived alongside.

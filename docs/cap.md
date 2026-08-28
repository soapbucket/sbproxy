# CAP token verification
*Last modified: 2026-08-27*

CAP (Crawler Authorization Protocol) is a JWT-based capability-token format for agent and crawler traffic. An agent presents a token in `CAP-Token: <jwt>` or `Authorization: CAP <jwt>`, and the token itself carries what the bearer may do: which paths, at what request rate, up to how many bytes a day. SBproxy ships the verifier side, the latency-critical half that runs on every request; tokens are minted by whichever issuer your deployment trusts, and the config names that issuer's keys.

This pairs naturally with the crawler-metering surfaces: [ai-crawl-control.md](ai-crawl-control.md) challenges unpaid crawlers, and a CAP token is how a paid or contracted one proves its grant. The verified subject also feeds [trust-tiers.md](trust-tiers.md) and access-log attribution.

## Config

```yaml
origins:
  "content.example.com":
    authentication:
      type: cap
      jwks_url: https://issuer.example.com/.well-known/cap/keys.json
      audience: content.example.com
      require_agent_binding: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `jwks_url` | string | unset | Remote JWKS endpoint holding the issuer's public keys. One of `jwks_url` or `jwks_static` is required; `jwks_url` wins when both are set, so a deployment can rotate from static keys to a fetched set without a flag day. |
| `jwks_static` | object | unset | Inline JWKS document, for offline or pre-issued-token deployments with no issuer endpoint. |
| `jwks_refresh_secs` | int | `3600` | Remote JWKS cache interval, clamped to at least 30 seconds. |
| `audience` | string | request `Host` | Explicit audience the token's `aud` must equal. Unset means the token must name the host it is presented to. |
| `require_agent_binding` | bool | `false` | Require the token's `sub` to match the agent identity the resolver chain attached to the request. When set and no identity resolved, the request is refused: the binding fails closed. |

## What the verifier checks, in order

1. **Signature** against the JWKS (Ed25519 keys in the examples; anything the key set advertises).
2. **Standard claims**: `exp` not passed, `iat` not in the future, `iss` present, `aud` equal to the configured audience or the request `Host`, and `cap_v == 1`.
3. **Subject binding**: when the agent-class resolver chain has attached an `agent_id` to the request, the token's `sub` must match it. `require_agent_binding: true` makes a missing resolved identity a refusal rather than a pass.
4. **Route grant**: the request path must match the token's `glob` allowlist claim.
5. **Rate grant**: the token's `rps` claim is enforced in a per-subject token bucket, after everything above has passed, so an attacker cannot spend a subject's budget with bad tokens.

A verified token puts a principal on the request: the subject becomes the rate-limit and attribution identity, and the token id (`jti`) lands in the access log as `cap_token_id`, so per-token consumption is queryable.

## What the caller sees

| Outcome | Response |
|---|---|
| Verified | Request proceeds with the token's principal attached. |
| No token | `401` with `WWW-Authenticate: License`, the RSL 1.0 challenge, so a crawler discovers the scheme. |
| Token invalid (bad signature, expired, malformed, JWKS unreachable) | `401` with `WWW-Authenticate: License error="<code>"`, codes like `invalid_token`, `expired_token`, `directory_unavailable`. An unreachable JWKS refuses rather than admits: verification fails closed. |
| Token valid but not for this (wrong audience, subject mismatch, path outside `glob`) | `403` with codes like `invalid_audience`, `agent_mismatch`, `agent_binding_required`, `path_not_authorized`. The distinction is deliberate: `401` means retry with a better token, `403` means this token does not authorize this request. |
| Over the token's `rps` grant | `429` with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After`. |

## Honest limits

- **The daily byte budget is not a hard cutoff.** The token's `bytes` claim (max bytes per UTC day) is verified, surfaced on the principal, and attributable per token through the access log, but nothing in the current binary severs traffic when the budget is exhausted. Enforce it downstream off the attribution data, or treat it as a contractual term rather than a technical one.
- **Issuance is out of scope.** SBproxy verifies; it does not mint tokens or run an issuer endpoint. The `jwks_static` shape exists precisely so a deployment can pre-issue tokens with its own tooling and hand the gateway only the public keys.
- **No licensing issuer, and no marketplace bridge.** There is no RSL Open Licensing Protocol issuer here (the four-step flow that mints Ed25519-signed license tokens for AI crawlers), and no bridge to IAB's Content Authorization Marketplace Protocol. The gateway ships the verifying and challenging halves of crawler licensing: it can refuse an unlicensed crawler ([ai-crawl-control.md](ai-crawl-control.md)), publish its terms ([rsl.md](rsl.md)), and verify a token somebody else minted. Minting and settling are the parts a licensing business runs, and they are not in this binary. If you see the issuer named anywhere as a thing to configure, that is a documentation bug rather than a hidden feature.

## See also

- [ai-crawl-control.md](ai-crawl-control.md) - the challenge side: making unpaid crawlers acquire a grant.
- [use-case-meter-crawlers.md](use-case-meter-crawlers.md) - the end-to-end crawler-metering walkthrough.
- [trust-tiers.md](trust-tiers.md) - how a CAP verification or denial moves the request's trust tier.
- [glossary.md](glossary.md) - the one-paragraph definition.

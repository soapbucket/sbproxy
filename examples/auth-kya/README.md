# Know Your Agent (KYA)

*Last modified: 2026-08-27*

Admit AI agents by identity rather than by credential. An agent
presents a token its identity provider signed, in the `X-Skyfire-KYA`
header, and the proxy verifies it against the issuer's published key
set and revocation list. What a verified token establishes is not just
"allowed": it is an agent id, the vendor operating the agent, the class
of agent it claims to be, and a spend balance.

The spend balance is the reason to reach for this over
[`bot_auth`](../web-bot-auth/) or [`cap`](../auth-cap/). Those prove a
crawler is who it says it is. This one also tells you whether it can
pay, before the request reaches an upstream that bills for it.

## The verification, in order

1. Decode the token header, and refuse anything that is not ES256 or
   RS256. A token cannot talk the verifier down to `none`.
2. Check `iss` against `issuers:`, **before any network fetch**. A
   token naming an issuer you did not list is refused without the proxy
   dialing the URL the token asked it to.
3. Fetch the issuer's `/.well-known/jwks.json` (cached), and resolve
   the signing key by `kid`.
4. Verify the signature.
5. Verify `exp` and `iat`, with two seconds of clock skew.
6. Verify `aud` names this gateway's hostname, or the literal `*`.
7. Check the token's `jti` against the issuer's
   `/.well-known/kya-denylist.json` (cached). A `404` there is an empty
   denylist, not an outage: an issuer that has revoked nothing does not
   have to publish the document.
8. Compare the token's balance against `min_kyab_balance`, when one is
   set.

## What each outcome answers

| Outcome | Status | Why that status |
|---|---|---|
| Verified, balance clears the floor | passed through | The `sub` claim becomes the request's principal |
| No `X-Skyfire-KYA` header | `401` | Nothing was presented |
| Expired, revoked, or badly signed | `401` | A credential was presented and it did not verify |
| Verified, balance below `min_kyab_balance` | `402` | The credential is fine and the account is empty. A paying client can act on that; a `401` would send it to fetch a token it already has |
| Verified, balance in another currency | `402` | The floor is denominated in `min_kyab_currency`. 5000 COP is about a dollar twenty, so a numeric comparison would clear a floor meaning ten dollars |
| Verified, no `jti`, issuer publishes revocations | `401` | A token with no `jti` cannot be revoked, and admitting it past a check that cannot run makes the revocation promise false for that class of token |
| Issuer's JWKS or denylist unreachable | `503` | The proxy could not verify, so it refuses. `fail_open: true` inverts this |

## You need an issuer

The shipped config points at `https://issuer.test.sbproxy.dev`, which
is a placeholder. Without an issuer publishing a key set there, every
request answers `503`, which is the fail-closed posture doing its job.

To exercise this locally you need three things: an ES256 or RS256 key
pair, a JWKS document served at
`<issuer>/.well-known/jwks.json`, and a token signed with that key
carrying `iss` (matching the configured issuer exactly), `aud`
(`agents.local` or `*`), `exp`, `jti`, `sub`, `agent_id`, `vendor`,
`agent_class`, `kya_version`, and optionally `kyab_balance`:

```json
{
  "iss": "https://issuer.test.sbproxy.dev",
  "aud": "agents.local",
  "sub": "agent-7f21",
  "jti": "01JB0Z3M2K",
  "exp": 1788000000,
  "agent_id": "acme-research-bot",
  "vendor": "Acme",
  "agent_class": "assistant",
  "kya_version": "1.0",
  "kyab_balance": {
    "amount": 2500,
    "currency": "USD",
    "expires_at": "2027-01-01T00:00:00Z"
  }
}
```

Point `issuers[].url` at wherever you serve that JWKS. The URL must be
`https://`: the key set fetched from it is the root of trust for every
token the issuer signs, so a plaintext fetch would let anyone on the
path mint accepted tokens.

## Run

```bash
make run CONFIG=examples/auth-kya/sb.yml
```

## Try it

```bash
# 200 - the token verifies and 2500 clears the 1000 floor
curl -i -H 'Host: agents.local' -H "X-Skyfire-KYA: $TOKEN" \
     http://127.0.0.1:8080/get

# 402 - verified agent, balance below min_kyab_balance
curl -i -H 'Host: agents.local' -H "X-Skyfire-KYA: $BROKE_TOKEN" \
     http://127.0.0.1:8080/get

# 402, from the policy rather than the provider - the agent clears the
# origin's floor but not this route's
curl -i -H 'Host: agents.local' -H "X-Skyfire-KYA: $TOKEN" \
     http://127.0.0.1:8080/expensive

# 401 - nothing presented
curl -i -H 'Host: agents.local' http://127.0.0.1:8080/get
```

## What policy can read

The `expression` policy in the shipped config is the point of the
identity half. Everything the verified token carried is addressable:

| Expression | Value |
|---|---|
| `request.kya.verdict` | `verified`, or `directory_unavailable` when `fail_open: true` admitted the request anyway. Every other verdict refuses, so no policy runs to read it |
| `request.kya.agent_id` | The agent identifier the **token** carried. Not `request.agent_id`, which is what the resolver worked out from the User-Agent |
| `request.kya.agent_class` | The agent class the token claimed |
| `request.kya.vendor` | The vendor from the token |
| `request.kya.kya_version` | The KYA spec version the token was minted under |
| `request.kya.kyab_balance.amount` | The balance, in the smallest currency unit, or `0` |

The same fields are readable from Lua, JavaScript, and WASM. A balance
whose `expires_at` has passed reads as `0`, and so does one whose
`expires_at` does not parse: an allowance the issuer has already
withdrawn is not one to spend, and an unparseable expiry is not a
reason to treat it as unlimited.

The verdict also feeds the [trust tier](../../docs/trust-tiers.md). A
verified token earns `strong`, a presented-and-rejected one drops the
request to `suspicious`, and an unreachable issuer stays neutral,
because a fetch failure is not evidence about the caller.

## Two things the caching cannot do

The JWKS and the denylist are cached per issuer for
`jwks_refresh_interval_secs`, with `stale_grace_secs` of extra life
while a refresh is failing. **Verdicts are not cached at all.** A token
is verified on every request, because a cached verdict is a revocation
the proxy has decided not to see, and revocation is half of why this
provider exists.

What the stale-grace window costs: while an issuer is unreachable, a
token revoked during the outage still verifies, because the proxy is
serving the denylist it last fetched. Shorten `stale_grace_secs` to
trade availability for that, or set `fail_open: false` (the default) so
that past the window the origin refuses rather than guessing.

## Watching it

`sbproxy_kya_verdicts_total{verdict}` counts every verification.
`revoked` and `expired` are agents presenting credentials their issuer
withdrew; `insufficient_balance` is a verified agent that cannot pay;
`directory_unavailable` is an issuer the gateway could not reach with
no usable cached copy. The "Agent Identity Verdicts (KYA)" panel on
the `SBProxy Security` dashboard draws them all. The issuer is
deliberately not a metric label.

## See also

- [docs/authentication.md](../../docs/authentication.md) - which provider fits which caller.
- [docs/configuration.md](../../docs/configuration.md#kya) - the field table.
- [docs/trust-tiers.md](../../docs/trust-tiers.md) - what a verdict does to `request.trust_tier`.

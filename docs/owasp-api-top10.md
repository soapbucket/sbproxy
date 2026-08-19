# OWASP API Top 10 pack

*Last modified: 2026-08-18*

`owasp_api_top10` is a policy pack: one config entry that expands into
the real, individually-documented policies and transforms this page
names, rather than a new enforcement mechanism of its own. Add it to an
origin's `policies:` list, name the items you want, and the compiler
does the rest before anything else in that list is even parsed.

```yaml
policies:
  - type: owasp_api_top10
    enable: all                # or a list: [api1, api4, api5, api7, api8]
    posture: report_only       # pack-wide default; omit for the same effect
    per_item:
      api1:
        posture: enforce       # override one item's posture
      api3:
        response_exclude_fields: [ssn, internal_notes]
```

This page is the per-item reference: what each of the ten OWASP API
Security Top 10 (2023) items synthesizes, its default posture and why,
how to move it from `report_only` toward `enforce`, and what an
operator still has to supply. For the pack's mechanics (parsing,
back-off, the manifest), see [The pack mechanics](#the-pack-mechanics)
below. For a hands-on walkthrough, start with
[`examples/owasp-api-top10/`](../examples/owasp-api-top10/) (`enable:
all`) or [`examples/owasp-api-selective/`](../examples/owasp-api-selective/)
(named items, `per_item` overrides, the `response_exclude_fields`
demo). For the same coverage configured entirely by hand, without the
pack, see [api-security.md](api-security.md).

## The pack mechanics

**Expansion.** The compiler reads `type: owasp_api_top10` before any
policy is compiled, expands it into concrete policy and transform
entries, and removes the pseudo-entry itself. It never reaches a
policy module's own config parser; only what it synthesizes does.

**Back-off.** If an origin already authors a policy of the type an
item would synthesize, the pack leaves it alone entirely, posture and
all, and the manifest reports `operator_authored` for that item. Two
items (`api4`, `api8`) synthesize more than one policy; each backs off
independently, so authoring just one of them yourself still gets the
pack's coverage for the rest, and the manifest names exactly which.

**Posture.** `posture` (pack-wide, default `report_only`) and
`per_item.<item>.posture` control the synthesized config, not
necessarily the live outcome. It threads into every synthesized
policy's own report-only knob when one exists. Today, that is exactly
one place: `api1`/`api5`'s shared `object_authz` entry, where it flips
`test_mode`. Every other synthesized policy in this pack version
(`request_limit`, `rate_limiting`, `concurrent_limit`,
`ddos_protection`, `security_headers`, `http_framing`,
`json_projection`) has no report-only mode at all, so posture has no
effect on those; they enforce (or, for `security_headers`, simply
inject headers) the moment they are synthesized, at either posture.
Do not read `posture: report_only` as a global soft-launch switch: for
most of this pack's items it is a no-op. It is a separate axis from
whether a piece is synthesized *at all*: `rate_limiting` and
`ddos_protection` (`api4`) and `security_headers` (`api8`) each have
their own synthesis gate unrelated to posture - see those items below.

**The honest manifest.** Every enabled item resolves to exactly one of
five states, never a silent no-op: `enforced`, `report_only`,
`needs_operator_input`, `operator_authored`, or `not_covered`.
`enable: all` always produces ten rows.

## The states, briefly

- **enforced** - the pack synthesized something and it blocks (or, for
  a header-injection policy, simply applies) regardless of posture, or
  the item's control already runs outside the policy chain entirely.
  Coverage can still be partial: `api4` reports `enforced` once its
  rate-shaped pieces have a budget, even though its reason still names
  anything the operator's own config is standing in for.
- **report_only** - reserved for an item whose synthesis both exists
  and has a real report-only knob that the pack-wide or per-item
  posture actually gates. No item in this pack version resolves here
  today; see the posture note above for why.
- **needs_operator_input** - the pack synthesized only part of an item
  (or a slot - an empty rule set, a missing field list - that does
  nothing at all) until an operator supplies what only they can: an
  ownership mapping, a role rule, a field list, or (`api4`) a
  requests-per-second budget.
- **operator_authored** - the origin already authors the policy type
  this item would have synthesized; the pack backs off and leaves it
  exactly as configured.
- **not_covered** - no synthesis is wired for this item in this pack
  version, it has no gateway control at all, or (`api8` on an action
  that never applies response-phase policies, such as `mcp` or
  `storage`) this origin's action type cannot run the control that
  would apply. The reason says which.

## api1: Broken Object Level Authorization

**Risk.** `GET /orders/1042` returns order 1042 to whoever asks,
because the handler checked that you are logged in, not that the
order is yours.

**Synthesizes.** An `object_authz` entry with empty `object_rules` and
`enumeration.enabled: true`. Shared with `api5` when both are enabled:
enabling either first, then the other, produces one entry, not two.

**Default posture and why.** `needs_operator_input`, regardless of
`posture`. With `object_rules` empty there is no ownership rule for
the policy to match a request against, so BOLA checking has nothing
to evaluate. `enumeration.enabled: true` is live immediately, though:
with no rules, the policy falls back to a path-shape heuristic and
reports an identified caller who sweeps many distinct ids as an
enumeration violation, for audit only (counted and logged, never
blocked, regardless of posture). Adding an `object_rules` entry
scopes enumeration to rule-captured ids and makes violations follow
the posture.

**report_only -> enforce.** `posture: enforce` (pack-wide or
`per_item.api1.posture: enforce`) flips the synthesized entry's
`test_mode` from `true` to `false`. This is real, tested config
threading, and it changes nothing observable on its own: with
`object_rules` empty, `test_mode` has no rule to apply to. It becomes
the switch that decides "audit" vs. "block" the moment you add a rule,
not before.

**Operator input needed.** An `object_rules` entry naming the path
template, the owner path segment, and the object-id segment,
plus a trustworthy identity source (`principal.owner_from: sub`, the
default and the safe choice, reads the verified auth subject; see
[object-authz.md](object-authz.md)).

**Back off yourself.** Author your own `object_authz` (or its alias
`bola`) policy on the origin and the pack adds nothing; your entry and
its posture stand exactly as configured.

## api2: Broken Authentication

**Risk.** A bearer token with no audience check, a JWT validated
against the wrong issuer, a session that survives logout: each is
ordinary and each is enough.

**Synthesizes.** Nothing. `not_covered`.

**Why not covered.** Strong authentication is a choice of provider
(`jwt`, `oidc`, `api_key`, `bearer_token`, and others), not a default
this pack can pick on your behalf. See
[api-security.md](api-security.md#authentication-that-is-weaker-than-it-looks)
for the direct configuration, or [auth-oidc.md](auth-oidc.md) for the
full relying-party flow.

## api3: Broken Object Property Level Authorization

**Risk.** Mass assignment on the way in (a request sets a field it
should never be allowed to set) and excessive data exposure on the
way out (a response returns fields the caller had no business
seeing), the same underlying gap wearing two directions.

**Synthesizes.** Request side: nothing. `openapi_validation` and
`request_validator` both require operator-supplied content (a spec or
a JSON Schema) with no universal default, the same structural gap as
`api1`'s ownership rules; the pack only detects whether you already
author one. Response side: a `json_projection` transform
(`fields: <your list>`, `exclude: true`, `failure_posture: closed`)
appended to the origin's `transforms:`, but only when
`per_item.api3.response_exclude_fields` supplies the field list.
`json_projection` already existed before this pack; the pack wires it,
it does not invent it.

**Scope: top-level object fields only.** `json_projection` filters
the **top-level keys of a JSON object** response body. A JSON array
body, or a sensitive field nested inside an object or array rather
than sitting at the top level, passes through completely unfiltered -
this is not "every JSON response body," and the fields you list are
only actually stripped when the response is shaped as a flat object
carrying them at the top. Confirm your response shape before relying
on this for a field that matters. `failure_posture: closed` (set on
every synthesized entry) means an oversized or unparseable response
body is refused rather than shipped raw and unfiltered - without it,
an attacker-influenceable oversized body would ship the very fields
this piece exists to strip.

**Default posture and why.** `needs_operator_input` when no field
list is supplied: neither half does anything. The moment
`response_exclude_fields` is set, the item as a whole reports
`enforced`, because the response half is then genuinely,
unconditionally active for a top-level-object response shape; the
reason still names the request-side gap by name so the label does not
overstate what is actually covered.

**report_only -> enforce.** There is no report-only step for this
item. `json_projection` has no audit mode; supplying the field list
turns stripping on, omitting it leaves the response untouched. The
graduated step available here is the field list itself: start with
the fields you are certain about, add more once you have confirmed no
caller depends on them.

**Operator input needed.**
`per_item.api3.response_exclude_fields: [field, ...]` for the
response half. For the request half, author `openapi_validation`
(`mode: log` to observe real traffic before blocking, or `mode:
enforce` with a spec in hand) or `request_validator` directly; the
pack detects either and says so in the reason, but synthesizes
neither.

## api4: Unrestricted Resource Consumption

**Risk.** An endpoint with no limit is a denial-of-service primitive
and a credential-stuffing oracle at once, and also how one retry loop
takes a backend down.

**Synthesizes.** Four independently-backing-off pieces, in two safety
tiers.

Always synthesized, safe to default blind: `request_limit`
(`max_body_size: 1048576` [1 MiB], `max_header_count: 64,
max_url_length: 2048` - a structural cap on the request's own shape,
not on who sent it) and `concurrent_limit` (`max: 200`, `key_by:
global` - one shared in-flight budget for the whole origin, also not
keyed on caller identity).

Synthesized **only when you supply `per_item.api4.rps`**:
`rate_limiting` (`requests_per_second: <rps>`, `burst: round(rps * 2)`)
and `ddos_protection` (`requests_per_second: ceil(burst * 1.5)` - not
`rps` itself; see the headroom note just below; `block_duration_secs`
stays at the module's own 300-second default). Absent `rps`, neither
is synthesized and the item reports `needs_operator_input`, even
though `request_limit`/`concurrent_limit` are already running.

Authoring any one of the four yourself backs that specific piece off;
the rest still land under the rules above.

> **Read this before setting `per_item.api4.rps`.** `rate_limiting`
> and `ddos_protection` both key on the caller's *observed* IP by
> default. Sitting behind a load balancer or reverse proxy with no
> `proxy.trusted_proxies` configured means sbproxy sees every caller
> as the load balancer's one IP - so a per-caller budget becomes a
> *shared* budget across every real client, and the first burst of
> real traffic that exceeds it 429s (or, for `ddos_protection`, blocks
> for five minutes) every other client sharing that IP too. This is a
> real outage class this pack found and fixed by refusing to guess a
> number. Before setting `rps`: confirm `proxy.trusted_proxies` covers
> your load balancer's address (or confirm this origin has no load
> balancer in front of it), then pick a per-caller budget that fits
> your real traffic - not the module's old blind default. See
> [Trusted proxies and forwarding headers](configuration.md#trusted-proxies-and-forwarding-headers)
> for how sbproxy resolves the caller's address behind a proxy chain.

> **Why `ddos_protection`'s threshold is not `rps`.** `ddos_protection`
> has no throttle-first step the way `rate_limiting`'s token bucket
> does: the moment an IP's count inside the current 1-second window
> exceeds the threshold, that IP is hard-blocked for
> `block_duration_secs` (five minutes at the module default). Setting
> the threshold to the same `rps` value used for `rate_limiting` meant
> a client legitimately bursting between `rps` and `rate_limiting`'s
> own `burst` ceiling - squarely inside what `rate_limiting` already
> tolerates - tripped a five-minute IP block instead of an ordinary
> 429. The pack sets `ddos_protection`'s threshold to
> `ceil(burst * 1.5)` instead: comfortably above `rate_limiting`'s own
> tolerance, so `ddos_protection` only fires meaningfully above what
> `rate_limiting` already lets through, never inside it.

**Default posture and why.** `needs_operator_input` until `rps` is
set, then `enforced`. None of the four pieces has a report-only mode
either way; each blocks past its configured limit regardless of
`posture` - `posture` only ever affects whether a violation is
audited or blocked, and none of these four ever audits.

**report_only -> enforce.** No-op for this item; there is no
report-only path to move along. `posture` is accepted but does
nothing here.

**Operator input needed.** `per_item.api4.rps` (after confirming
`trusted_proxies`, above) to get the rate-shaped half of this item's
coverage; `request_limit`/`concurrent_limit` need nothing. Or author
your own `request_limit` / `rate_limiting` / `concurrent_limit` /
`ddos_protection` to replace the pack's piece for that one control
while keeping the rest.

## api5: Broken Function Level Authorization

**Risk.** `DELETE /admin/users/{id}` is reachable by any caller whose
token merely validates, because the handler checked authentication
and not the role a destructive action requires.

**Synthesizes.** Shares `api1`'s `object_authz` entry when both are
enabled (adds nothing new to the config). Enabled alone, synthesizes
its own `object_authz` entry with empty `function_rules`.

**Default posture and why.** `needs_operator_input`, regardless of
`posture`, for the same structural reason as `api1`: with
`function_rules` empty there is no rule to check a request's method or
required role against.

**report_only -> enforce.** Threads into the same `test_mode` field as
`api1` for consistency; with no rules, it has nothing to apply to
either.

**Operator input needed.** A `function_rules` entry naming the
privileged path, its method set, and the required role
(`require_role`). Reading roles from a header instead of a trusted
claim needs the explicit `principal.trust_role_header: true` opt-in;
see [object-authz.md](object-authz.md).

## api6: Unrestricted Access to Sensitive Business Flows

**Risk.** A legitimate action (buying a ticket, placing a bid, sending
an invite) automated at superhuman speed defeats a business rule no
single request violates on its own.

**Synthesizes.** Nothing. `not_covered`.

**Why not covered.** No purpose-built control exists for this class;
composing `rate_limiting`, `concurrent_limiting`, `object_authz`
`function_rules`, and bot/`web_bot_auth` checks is the operator's job,
because which flows count as sensitive is inherently a business
decision, not one a gateway can infer from shape alone.

## api7: Server Side Request Forgery

**Risk.** The gateway becomes a proxy for a destination the attacker
picked, including cloud metadata endpoints, turning a fetch feature
into a credential leak.

**Synthesizes.** Nothing. `enforced` with zero synthesized policies:
sbproxy's outbound dial path already refuses private, loopback, and
link-local upstream targets by default, at every call site that dials
a caller-influenced or configured URL (webhook targets, AI provider
base URLs, RAG HTTP providers, alerting channels, A2A push targets,
external guardrails), independent of whether this pack is enabled at
all.

**Scope: sbproxy's own outbound dials only.** This guard covers
requests *sbproxy itself* makes on the proxy process's behalf. It does
**not** cover the backend application's own server-side URL fetching -
a caller supplies a URL, or a value the app resolves into one, and the
app's own code fetches it - which is the API7:2023 risk as OWASP
defines it, and which happens entirely behind this origin's action,
somewhere this pack cannot see or guard. If your backend fetches
caller-influenced URLs itself, that check belongs in the backend, not
here.

**Default posture and why.** `enforced`, always, for what this guard
does cover. This is not a policy the pack can toggle; it names an
already-running control rather than adding one.

**report_only -> enforce.** Not applicable; there is nothing this
pack turns on or off for this item.

**Operator input needed.** None to get the guard. Review
`proxy.extensions.upstream.allow_private_cidrs` directly if it looks
unusually broad; this pack does not compute that check itself.

## api8: Security Misconfiguration

**Risk.** The boring stuff nobody set: no `X-Frame-Options`, no
`X-Content-Type-Options`, and request framing ambiguous enough for one
hop to disagree with the next about where a request ends.

**Synthesizes.** Two independently-backing-off pieces: `security_headers`
(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`; HSTS and CSP deliberately left out,
since HSTS assumes the origin is always served over TLS and CSP is
response-shape-specific) and `http_framing` (refuses dual
`Content-Length`/`Transfer-Encoding`, duplicate `Content-Length`,
malformed `Transfer-Encoding`, duplicate `Transfer-Encoding`, and
control characters in header values; hard-coded, no tunable fields).
A managed `waf` (Core Rule Set) default is deliberately not part of
this item in this pack version; configure `waf` directly for that.

**`security_headers` needs an action that applies response-phase
policies.** That covers the proxied actions (`proxy`, `load_balancer`,
`websocket`, `a2a`, `graphql`, `grpc`) and the generated-response
actions (`static`, `mock`, `echo`, `beacon`, `redirect`), which carry
response-phase policy headers the same way a proxied origin does. An
origin whose action answers through its own protocol write path -
`mcp`, `noop`, `ai_proxy`, `storage`, or a plugin action - does not,
so `security_headers` is not synthesized there; the manifest names the
gap by action type instead of claiming coverage nothing runs.
`http_framing` runs at request phase, independent of action type, and
always synthesizes regardless.

**Default posture and why.** `enforced` whenever at least one piece
lands (which `http_framing` always does), unconditionally. Neither
piece has a report-only mode: headers always inject, framing checks
always block. If this origin's action skips response-phase
enforcement and the operator already authors `http_framing`
themselves too, nothing from the pack is actually running for this
item and it reports `not_covered` instead.

**report_only -> enforce.** No-op for this item.

**Operator input needed.** None for baseline coverage on a proxied or
generated-response origin. On an `mcp`/`storage`/other
own-write-path origin, `security_headers` needs to be configured on
the app itself (or the route moved to a covered action type) if
response headers matter for it. Layer `waf` on top yourself for
broader misconfiguration coverage; see
[waf-options.md](waf-options.md).

## api9: Improper Inventory Management

**Risk.** An old API version, or a route nobody remembered to
retire, stays reachable because there is no accurate map of what is
actually exposed.

**Synthesizes.** No policy. Sets the origin's own `expose_openapi`
field to `true` when it was `false` (the default); this is the only
item that changes an origin-level field directly rather than adding a
`policies:` or `transforms:` entry.

**Default posture and why.** `enforced` whenever enabled: turning
emission on never blocks traffic, so this is a report, not a block.
The reason draws the real tradeoff rather than presenting a free win:
publishing route shape at `/.well-known/openapi.json` (and `.yaml`)
is a disclosure decision, worth reviewing before shipping `enable:
all` or `api9` alone to a production origin. It only reflects what
this gateway routes: a backend route sbproxy never sees (a shadow
API) is not listed, and there is no sunset/deprecation enforcement
for an old version still reachable through versioning.

**report_only -> enforce.** Not applicable; there is no blocking mode
for this item.

**Operator input needed.** None to turn it on. Decide whether the
disclosure is acceptable for this origin first; see
[openapi-emission.md](openapi-emission.md).

## api10: Unsafe Consumption of APIs

**Risk.** Trusting a third-party API's response as blindly as your
own service's: an unbounded redirect chain, an unbounded response
body, or an unexpected content type from an integration you do not
control.

**Synthesizes.** Nothing. `not_covered`.

**Why not covered.** No gateway control exists for this today.
sbproxy's own outbound calls to third-party APIs have no
response-handling safety net (redirect limits, response-size caps,
content-type validation) beyond `api7`'s destination checks.

## The manifest

`enable: all` (or any explicit list) always produces one row per
enabled item; nothing is ever silently skipped. Two surfaces carry the
same outcome.

**`sbproxy plan`.** Planning a config that carries the pack names
every item and its resolved state in the plan text, alongside the
ordinary origin diff, so a reviewer sees `needs_operator_input` and
`not_covered` items at plan time rather than discovering them only
once the config is running. See [manual.md](manual.md#plan---diff-a-proposed-config-against-a-baseline)
for the base diff format.

**`GET /admin/owasp-api-pack`.** Same auth as the rest of the admin
surface (HTTP Basic against the configured admin identity, or the
browser session from `POST /admin/login`; see
[admin-api-reference.md](admin-api-reference.md#authentication)).

```json
{
  "origins": {
    "<hostname>": {
      "enabled": ["api1", "..."],
      "posture": "enforce" | "report_only",
      "items": [
        {
          "item": "api1",
          "title": "Broken Object Level Authorization",
          "state": "enforced" | "report_only" | "needs_operator_input" | "operator_authored" | "not_covered",
          "reason": "<one sentence or more, safe to show an operator verbatim>",
          "synthesized": ["object_authz"]
        }
      ]
    }
  }
}
```

An origin with no `owasp_api_top10` entry is absent from `origins`.
With no pack configured anywhere, the endpoint returns `200 {"origins":
{}}`. See [`examples/owasp-api-top10/`](../examples/owasp-api-top10/)
for both surfaces read back against a running config.

## See also

- [`examples/owasp-api-top10/`](../examples/owasp-api-top10/) -
  `enable: all`, one refused request per item that enforces, and the
  manifest read back from `sbproxy plan` and the admin endpoint.
- [`examples/owasp-api-selective/`](../examples/owasp-api-selective/) -
  named items, `per_item` overrides, and `response_exclude_fields`.
- [api-security.md](api-security.md) - the same coverage, configured
  entirely by hand, with the reasoning behind each control.
- [configuration.md](configuration.md#owasp_api_top10-pack) - the
  `owasp_api_top10` field reference.
- [object-authz.md](object-authz.md) - the full `object_authz`
  matcher surface `api1` and `api5` synthesize into.
- [openapi-emission.md](openapi-emission.md) - what `expose_openapi`
  actually publishes, in depth.
- [transforms.md](transforms.md) - `json_projection` and every other
  shipped transform kind.
- [admin-api-reference.md](admin-api-reference.md) - the admin server's
  full route reference, including authentication.

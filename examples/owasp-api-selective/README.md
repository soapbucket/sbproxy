# The OWASP API Top 10 pack, adopted selectively

*Last modified: 2026-08-18*

Most operators do not flip on `enable: all` on day one. This example is
the realistic path: name a handful of items, leave the pack-wide
posture at `report_only` (the default, and the safest place to start),
and promote one item at a time with a `per_item` override once you have
reviewed what it would have done. It also demonstrates the one
`per_item` field that is not a posture: `api3`'s
`response_exclude_fields`, which wires the pack's response-side
`json_projection` transform.

Four items are named: `api1`, `api3`, `api4`, `api8`. The origin is a
self-contained `static` action, so the example runs offline; the
`owasp-pack-selective.local` Host header reaches it on `127.0.0.1:8080`,
and the admin server (used to read the manifest back) is on
`127.0.0.1:9090`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

**api3's response side strips two fields before the client sees them.**
The upstream document (what the `static` action holds internally) has
four fields: `id`, `email`, `ssn`, `internal_notes`.
`per_item.api3.response_exclude_fields: [ssn, internal_notes]` tells
the pack to synthesize a `json_projection` transform excluding exactly
those two:

```bash
# Upstream body (what the static action emits internally; sbproxy's
# JSON serialization sorts object keys alphabetically):
# {"email":"alice@example.com","id":42,"internal_notes":"flagged for manual review","ssn":"123-45-6789"}

$ curl -s -H 'Host: owasp-pack-selective.local' \
       http://127.0.0.1:8080/customers/42
{"email":"alice@example.com","id":42}
```

`ssn` and `internal_notes` never reach the caller. This is the pack's
own answer to api3's excessive-data-exposure half: not a new
mechanism, `json_projection` already existed
([`examples/transform-json-projection/`](../transform-json-projection/)),
just wired automatically the moment you hand the pack a field list.

**api1's posture override changes the synthesized config, not the
outcome, because there is nothing to enforce yet.** The pack-wide
default is `report_only`; `per_item.api1.posture: enforce` promotes
just this one item, which flips the synthesized `object_authz` entry's
`test_mode` from `true` to `false`. But `api1`'s synthesized entry has
empty `object_rules` (this pack cannot infer your ownership model),
and with no rule to match, ownership checking has nothing to block
either way. What does run ruleless is the enumeration heuristic: it
reports an identified caller's id sweeps for audit only, in both
postures, and never blocks. The manifest still reports
`needs_operator_input`, not `enforced`, and says so:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack-selective.local"].items[] | select(.item=="api1")'
```

```json
{
  "item": "api1",
  "title": "Broken Object Level Authorization",
  "state": "needs_operator_input",
  "reason": "synthesized object_authz with empty object_rules and enumeration.enabled: true (test_mode: false, so a rule-derived violation is blocked). With object_rules empty the ruleless path-shape heuristic is active: an identified caller sweeping many distinct ids is reported as an enumeration violation for audit only (counted and logged, never blocked, regardless of posture). Real BOLA ownership coverage still needs an operator-authored object_rules entry, which this pack cannot infer; ...",
  "synthesized": ["object_authz"]
}
```

The promotion becomes real protection the moment you add
`object_rules` naming your own paths and owner claim, at which point
`test_mode: false` is what turns detection into a block. See
[docs/owasp-api-top10.md](../../docs/owasp-api-top10.md#api1-broken-object-level-authorization)
for that step.

**api4 enforces, because `per_item.api4.rps: 50` is set - read the
caveat in `sb.yml` before copying this.** `request_limit` and
`concurrent_limit` are always safe to default blind; `rate_limiting`
and `ddos_protection` are not, because both key on the caller's
*observed* IP by default. Behind a load balancer with no
`proxy.trusted_proxies` configured, every real client collapses to the
load balancer's single IP and shares one budget - a real outage class,
not a hypothetical one. Setting `rps: 50` here is safe only because
this example's `static` action has no load balancer in front of it;
confirm the same for your own origin (or that `trusted_proxies` covers
it) before setting this, and see
[docs/owasp-api-top10.md](../../docs/owasp-api-top10.md#api4-unrestricted-resource-consumption)
for the full guidance. [`examples/owasp-api-top10/`](../owasp-api-top10/)
deliberately leaves `rps` unset and shows the resulting
`needs_operator_input` state instead - read that one first if you
have not measured your traffic yet.

`request_limit`'s cap is still real, unconditional coverage regardless
of `rps`:

```bash
$ curl -i -H 'Host: owasp-pack-selective.local' \
       -H 'Content-Type: application/octet-stream' \
       --data-binary "$(head -c 1200000 /dev/urandom | base64)" \
       http://127.0.0.1:8080/customers/42
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"request entity too large"}
```

**api8 enforces too, but only half of it actually runs on this
`static` action.** `http_framing` runs at request phase, independent
of action type, and synthesizes and enforces here exactly as it would
on a `proxy` origin. `security_headers` does not: it only takes effect
in Pingora's response-phase filter, and a `static` action answers
entirely inside the request phase, never reaching that filter. The
pack does not synthesize `security_headers` here at all, and the
manifest's `synthesized` list for `api8` names only `http_framing` -
see the compact pass below. If you need response headers on a
`static`/`mock`/similar origin, configure them on the app itself, or
move the route to a `proxy`/`load_balancer` action.

## Read the manifest back

`enable: [api1, api3, api4, api8]` resolves exactly four rows, not
ten; only the enabled items appear. `api1`'s reason is shown in full
above. The compact pass over all four:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack-selective.local"] | {posture, items: [.items[] | {item, state, synthesized}]}'
```

```json
{
  "posture": "report_only",
  "items": [
    {"item": "api1", "state": "needs_operator_input", "synthesized": ["object_authz"]},
    {"item": "api3", "state": "enforced", "synthesized": ["json_projection"]},
    {"item": "api4", "state": "enforced", "synthesized": ["request_limit", "concurrent_limit", "rate_limiting", "ddos_protection"]},
    {"item": "api8", "state": "enforced", "synthesized": ["http_framing"]}
  ]
}
```

`api3` reads `enforced` for the whole item because its response half
is genuinely, unconditionally active once `response_exclude_fields`
is set; its `reason` still names the request-side gap
(`openapi_validation`/`request_validator`, neither configured here)
so the label does not overstate what is actually covered. `api8`'s
`synthesized` list naming only `http_framing`, not `security_headers`,
is the phase gap above made visible in the JSON, not just in prose.
`posture` at the top is the pack-wide default (`report_only`); it
applies to items whose synthesis has a posture-sensitive knob, which
today is only `api1`/`api5`'s shared `object_authz` entry.

## What this exercises

- Named items (`enable: [api1, api3, api4, api8]`) instead of
  `enable: all`
- `per_item.<item>.posture` promoting one item ahead of the pack-wide
  default
- `per_item.api3.response_exclude_fields` wiring a `json_projection`
  transform automatically
- `per_item.api4.rps` turning on `rate_limiting`/`ddos_protection`
  after confirming it is safe to (no load balancer in front of this
  origin) - the measure-first step
  [`examples/owasp-api-top10/`](../owasp-api-top10/) deliberately
  skips
- The honest gap between "the synthesized config changed" and "the
  live outcome changed": `api1`'s promotion is real and tested, and
  still does nothing until `object_rules` exists
- `api8` reporting `enforced` while its `synthesized` list still names
  only half its usual pieces, because this origin's `static` action
  cannot run the other half

## See also

- [docs/owasp-api-top10.md](../../docs/owasp-api-top10.md) - the
  per-item reference, including the report_only-to-enforce path for
  every item.
- [`examples/owasp-api-top10/`](../owasp-api-top10/) - `enable: all`,
  the full ten-item manifest, and the two items that block regardless
  of posture.
- [`examples/transform-json-projection/`](../transform-json-projection/)
  - `json_projection` configured directly, without the pack.
- [docs/api-security.md](../../docs/api-security.md) - the
  hand-configured version of everything this pack synthesizes.

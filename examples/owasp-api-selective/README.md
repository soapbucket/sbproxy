# The OWASP API Top 10 pack, adopted selectively

*Last modified: 2026-08-17*

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
`owasp-pack-selective.local` Host header reaches it on `127.0.0.1:8080`.

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
# Upstream body (what the static action emits internally):
# {"id":42,"email":"alice@example.com","ssn":"123-45-6789","internal_notes":"flagged for manual review"}

$ curl -s -H 'Host: owasp-pack-selective.local' \
       http://127.0.0.1:8080/customers/42
{"id":42,"email":"alice@example.com"}
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
and with no rule to match, the policy has nothing to block or flag
either way. The manifest still reports `needs_operator_input`, not
`enforced`, and says so:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack-selective.local"].items[] | select(.item=="api1")'
```

```json
{
  "item": "api1",
  "title": "Broken Object Level Authorization",
  "state": "needs_operator_input",
  "reason": "synthesized object_authz with empty object_rules and enumeration.enabled: true (test_mode: false, so a future violation is blocked). With object_rules empty this entry has no rule to match against any path, so it does not yet block or flag anything: real BOLA coverage needs an operator-authored object_rules entry, which this pack cannot infer. ...",
  "synthesized": ["object_authz"]
}
```

The promotion becomes real protection the moment you add
`object_rules` naming your own paths and owner claim, at which point
`test_mode: false` is what turns detection into a block. See
[docs/owasp-api-top10.md](../../docs/owasp-api-top10.md#api1-broken-object-level-authorization)
for that step.

**api4 and api8 enforce regardless of the pack-wide `report_only`
default,** because neither's synthesized policies have a report-only
mode. An oversized body is refused the same way it is in
[`examples/owasp-api-top10/`](../owasp-api-top10/README.md), whether
the pack's posture says `report_only` or `enforce`:

```bash
$ curl -i -H 'Host: owasp-pack-selective.local' \
       -H 'Content-Type: application/octet-stream' \
       --data-binary "$(head -c 1200000 /dev/urandom | base64)" \
       http://127.0.0.1:8080/customers/42
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"request entity too large"}
```

## Read the manifest back

`enable: [api1, api3, api4, api8]` resolves exactly four rows, not
ten; only the enabled items appear. `api1`'s reason is shown in full
above. The compact pass over all four:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack-selective.local"] | {posture, items: [.items[] | {item, state}]}'
```

```json
{
  "posture": "report_only",
  "items": [
    {"item": "api1", "state": "needs_operator_input"},
    {"item": "api3", "state": "enforced"},
    {"item": "api4", "state": "enforced"},
    {"item": "api8", "state": "enforced"}
  ]
}
```

`api3` reads `enforced` for the whole item because its response half
is genuinely, unconditionally active once `response_exclude_fields`
is set; its `reason` still names the request-side gap
(`openapi_validation`/`request_validator`, neither configured here)
so the label does not overstate what is actually covered. `posture`
at the top is the pack-wide default (`report_only`); it applies to
items whose synthesis has a posture-sensitive knob, which today is
only `api1`/`api5`'s shared `object_authz` entry.

## What this exercises

- Named items (`enable: [api1, api3, api4, api8]`) instead of
  `enable: all`
- `per_item.<item>.posture` promoting one item ahead of the pack-wide
  default
- `per_item.api3.response_exclude_fields` wiring a `json_projection`
  transform automatically
- The honest gap between "the synthesized config changed" and "the
  live outcome changed": `api1`'s promotion is real and tested, and
  still does nothing until `object_rules` exists
- Two items (`api4`, `api8`) that enforce unconditionally, independent
  of the pack's posture default

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

# The OWASP API Top 10 pack, all ten items

*Last modified: 2026-08-17*

One `type: owasp_api_top10` entry, `enable: all`, no other policy on the
origin. The compiler reads the pseudo-policy, expands it into real
synthesized policies before anything else in `policies:` is even parsed,
and removes the pseudo-entry so it never reaches a module. This example
walks all ten items: two live refusals from the two items whose defaults
are safe to block blind, one served document from the third, an honest
note on why the fourth cannot be demonstrated on a fixed-backend origin,
and the manifest that names all ten, read back two ways. For what every
item does and does not cover, see
[docs/owasp-api-top10.md](../../docs/owasp-api-top10.md).

This example uses `test.sbproxy.dev` as the upstream so it is fully
self-contained. The origin is reached on `127.0.0.1:8080` via the
`owasp-pack.local` Host header; the admin server is on `127.0.0.1:9090`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

Ordinary traffic is unaffected. Nothing in `enable: all`'s default
posture (`report_only`, since none is set) blocks a normal request:

```bash
$ curl -i -H 'Host: owasp-pack.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8

{"method":"GET","url":"/get","headers":{"host":"test.sbproxy.dev",...},"query":{},"timestamp":"..."}
```

**api4 (Unrestricted Resource Consumption) refuses an oversized body.**
The pack synthesizes `request_limit` with `max_body_size: 1048576` (1
MiB) as one of four independently-enforcing pieces
(`request_limit`, `rate_limiting`, `concurrent_limit`,
`ddos_protection`); none of the four has a report-only mode, so this
blocks regardless of the pack's default posture:

```bash
$ curl -i -H 'Host: owasp-pack.local' \
       -H 'Content-Type: application/octet-stream' \
       --data-binary "$(head -c 1200000 /dev/urandom | base64)" \
       http://127.0.0.1:8080/post
HTTP/1.1 413 Payload Too Large
content-type: application/json

{"error":"request entity too large"}
```

**api8 (Security Misconfiguration) refuses ambiguous request framing.**
The pack synthesizes `security_headers` and `http_framing`; the
latter refuses duplicate `Content-Length` headers before the request
reaches an upstream, one of five smuggling primitives it screens for.
`curl` cannot send a genuinely duplicated header reliably, so this uses
a raw socket:

```bash
$ printf 'POST /post HTTP/1.1\r\nHost: owasp-pack.local\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\nhello!' \
    | nc -w 2 127.0.0.1 8080
HTTP/1.1 400 Bad Request
content-type: application/json

{"error":"ambiguous framing: duplicate Content-Length"}
```

`security_headers`, the other half of api8, has no refusal semantics
of its own; it injects `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` on the way
out instead. Check for those on the first, successful `/get` call
above.

**api9 (Improper Inventory Management) serves a live document rather
than refusing anything.** Enabling it flips this origin's
`expose_openapi` from its default `false` to `true`, which is a
disclosure decision, not a block:

```bash
$ curl -sI -H 'Host: owasp-pack.local' \
       http://127.0.0.1:8080/.well-known/openapi.json
HTTP/1.1 200 OK
content-type: application/json
```

**api7 (Server Side Request Forgery) has nothing to curl on this
origin.** Its control is the outbound SSRF guard on sbproxy's own dial
path, which runs unconditionally on every caller-influenced or
configured destination this gateway dials (webhook targets, AI
provider base URLs, RAG HTTP providers, and similar), independent of
this pack. This origin's own backend is a fixed, operator-configured
URL, not a caller-influenced one, so there is no request against
`owasp-pack.local` that exercises it. The manifest still reports
`api7` as `enforced`, with zero synthesized policies, and names the
guard by config key (`proxy.extensions.upstream.allow_private_cidrs`)
in its reason. See `validate_url_resolved_blocks_private_ip`
(`crates/sbproxy-security/src/ssrf.rs`) for where that guard is
actually proven.

## Read the manifest back

Two surfaces carry the same ten-item outcome: `sbproxy plan` and a
dedicated admin endpoint. Neither ever produces a silent partial
result; `enable: all` always resolves to exactly ten rows, one state
each.

**`sbproxy plan`.** With no `--against` baseline, the whole origin is
new:

```bash
$ sbproxy plan -f sb.yml
```

```
+ origins.owasp-pack.local [reload] origin 'owasp-pack.local' added

Plan: 1 added, 0 changed, 0 removed. max-blast-radius: reload
```

The plan text also names every item this pack resolved and its state,
the same ten rows the admin endpoint below returns as JSON, so a
reviewer sees `api1`..`api10`'s outcome at plan time rather than
discovering it only once the config is running.

**The admin endpoint**, `GET /admin/owasp-api-pack`, same basic auth as
the rest of the admin surface. A compact pass first, one row per item:

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack.local"].items[] | {item, state}'
```

```json
{"item":"api1","state":"needs_operator_input"}
{"item":"api2","state":"not_covered"}
{"item":"api3","state":"needs_operator_input"}
{"item":"api4","state":"enforced"}
{"item":"api5","state":"needs_operator_input"}
{"item":"api6","state":"not_covered"}
{"item":"api7","state":"enforced"}
{"item":"api8","state":"enforced"}
{"item":"api9","state":"enforced"}
{"item":"api10","state":"not_covered"}
```

Four `enforced` (api4, api7, api8, api9), three `needs_operator_input`
(api1, api3, api5: each has a slot ready, none has the operator input
it needs yet), three `not_covered` (api2, api6, api10: no synthesis
exists for these in this pack version). None is silently skipped.

One full row, including the `reason` every state above carries and
the `synthesized` policy types behind it (abridged here; the live
`reason` is one full sentence per synthesized piece, so it runs
longer than this):

```bash
$ curl -s -u admin:admin http://127.0.0.1:9090/admin/owasp-api-pack \
    | jq '.origins["owasp-pack.local"].items[] | select(.item=="api4")'
```

```json
{
  "item": "api4",
  "title": "Unrestricted Resource Consumption",
  "state": "enforced",
  "reason": "synthesized request_limit (max_body_size: 1 MiB, ...), rate_limiting (100 req/s, burst 200, per-caller), concurrent_limit (max 200, global), and ddos_protection (module defaults). None has a report-only mode; posture has no effect on this item.",
  "synthesized": ["request_limit", "rate_limiting", "concurrent_limit", "ddos_protection"]
}
```

## What this exercises

- `type: owasp_api_top10` with `enable: all` and the pack's default
  (`report_only`) posture
- Four items (`api4`, `api7`, `api8`, `api9`) that enforce regardless
  of posture, because their controls have no report-only knob or run
  outside the policy chain entirely
- Three items (`api1`, `api3`, `api5`) that need operator-authored
  rules or a field list this pack cannot infer, honestly labeled
  `needs_operator_input` rather than silently skipped
- Three items (`api2`, `api6`, `api10`) with no synthesis wired in
  this pack version, labeled `not_covered` with a reason naming the
  gap
- The manifest read back from `sbproxy plan` and `GET
  /admin/owasp-api-pack`

## See also

- [docs/owasp-api-top10.md](../../docs/owasp-api-top10.md) - the
  per-item reference: what every item synthesizes, its default
  posture and why, and the report_only-to-enforce path.
- [`examples/owasp-api-selective/`](../owasp-api-selective/) - the
  realistic adoption path: named items, `per_item` overrides, and
  api3's `response_exclude_fields`.
- [docs/api-security.md](../../docs/api-security.md) - the
  hand-configured version of everything this pack synthesizes.
- [docs/configuration.md](../../docs/configuration.md) - the
  `owasp_api_top10` field reference.

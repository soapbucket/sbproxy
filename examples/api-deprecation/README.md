# API deprecation

*Last modified: 2026-09-05*

One origin, four versions of the same API, each at a different point in its lifecycle. A `deprecation:` block on a forward rule stamps the standard announcement headers (`Deprecation` per RFC 9745, `Sunset` per RFC 8594, `Link` relations for the successor and the docs) on exactly the requests that rule matches, counts every hit in `sbproxy_deprecated_requests_total`, and, where configured, retires the route with `410 Gone` once the sunset passes. The actions here are static so the example runs with no upstreams; the same blocks work unchanged on `proxy` actions.

| Path | Lifecycle stage |
|------|-----------------|
| `/v2/` | Current. No block, clean responses. |
| `/v1/` | Announced. Deprecated 2026-09-01, sunset at the start of 2030, still serving. |
| `/beta/` | Past sunset, default `serve` posture. Still answers; the counter labels each hit `past_sunset="true"`. |
| `/v0/` | Past sunset, `after_sunset: gone`. Refused with 410 and a body naming the successor. |

## Run

```bash
sbproxy serve -f sb.yml
```

## Announced: headers on a live route

`/v1/` is deprecated with a sunset years out. Every response says so, in the forms the RFCs specify: `Deprecation` is an RFC 9651 structured-field Date (`@1788220800` is 2026-09-01T00:00:00Z), `Sunset` is an HTTP-date, and the two `Link` relations point at the successor version and the human docs.

<!-- CAPTURE: curl -is -H 'Host: api.local' http://127.0.0.1:8080/v1/users -->

```text
HTTP/1.1 200 OK
content-type: application/json
content-length: 29
deprecation: @1788220800
sunset: Tue, 01 Jan 2030 00:00:00 GMT
link: <https://api.local/v2/>; rel="successor-version"
link: <https://developer.example.com/deprecation/v1>; rel="deprecation"
Date: Thu, 20 Aug 2026 13:49:08 GMT
Connection: keep-alive

{"version":"v1","user":"ada"}
```

## Past sunset, default posture: keep serving

`/beta/`'s sunset elapsed in 2020. The default `after_sunset: serve` keeps answering (a forgotten config never takes an API down by surprise); the headers show the elapsed dates and the usage counter flips to `past_sunset="true"` so the stragglers are visible.

<!-- CAPTURE: curl -is -H 'Host: api.local' http://127.0.0.1:8080/beta/users -->

```text
HTTP/1.1 200 OK
content-type: application/json
content-length: 31
deprecation: @1577836800
sunset: Mon, 01 Jun 2020 00:00:00 GMT
Date: Thu, 20 Aug 2026 13:49:08 GMT
Connection: keep-alive

{"version":"beta","user":"ada"}
```

## Past sunset, strict posture: 410 Gone

`/v0/` opted into `after_sunset: gone`. Requests after the sunset instant never reach the action; the refusal still carries the announcement headers and its body names the successor, so even the failure tells the caller where to go.

<!-- CAPTURE: curl -is -H 'Host: api.local' http://127.0.0.1:8080/v0/users -->

```text
HTTP/1.1 410 Gone
content-type: application/json
content-length: <LEN>
deprecation: @<EPOCH_S>
sunset: Mon, 01 Jun 2020 00:00:00 GMT
link: <https://api.local/v2/>; rel="successor-version"
Date: <DATE>
Connection: keep-alive

{"error":"gone","message":"This API has been retired.","sunset":"Mon, 01 Jun 2020 00:00:00 GMT","successor":"https://api.local/v2/"}
```

## The successor stays clean

`/v2/` carries no block, so its responses carry no deprecation headers. Per-rule scoping is the point: one origin, one config, and only the old versions announce.

<!-- CAPTURE: curl -is -H 'Host: api.local' http://127.0.0.1:8080/v2/users -->

```text
HTTP/1.1 200 OK
content-type: application/json
content-length: 29
Date: Thu, 20 Aug 2026 13:49:08 GMT
Connection: keep-alive

{"version":"v2","user":"ada"}
```

## Who has not migrated yet

The three deprecated-route hits above each incremented the counter under their rule's id, which is what the `route` label carries. `past_sunset` separates callers still arriving after the retirement date, which is the list you chase before flipping a route to `gone`, and `outcome` separates the ones still being served from the ones already refused with 410. `/v0/` shows up as `outcome="gone"` because that rule's posture is `gone` and its sunset has passed; `/beta/` is past its sunset too and still reads `served`.

<!-- CAPTURE: curl -s http://127.0.0.1:8080/metrics | grep deprecated -->

```text
# HELP sbproxy_deprecated_requests_total Requests that resolved to a deprecated route
# TYPE sbproxy_deprecated_requests_total counter
sbproxy_deprecated_requests_total{origin="api.local",outcome="gone",past_sunset="true",route="v0"} 1
sbproxy_deprecated_requests_total{origin="api.local",outcome="served",past_sunset="false",route="v1"} 1
sbproxy_deprecated_requests_total{origin="api.local",outcome="served",past_sunset="true",route="beta"} 1
```

## The spec agrees with the wire

`expose_openapi: true` publishes the generated OpenAPI document, and deprecated routes are marked there too: `deprecated: true` plus `x-sbproxy-sunset` and `x-sbproxy-successor` extensions carrying the same values as the headers. Docs renderers strike the operation through; the extensions carry the dates.

<!-- CAPTURE: curl -s -H 'Host: api.local' http://127.0.0.1:8080/.well-known/openapi.json | python3 -c "import json,sys; op=json.load(sys.stdin)['paths']['/v1/']['get']; print(json.dumps({k: op[k] for k in ('deprecated','x-sbproxy-sunset','x-sbproxy-successor') if k in op}, indent=2))" -->

```text
{
  "deprecated": true,
  "x-sbproxy-sunset": "Tue, 01 Jan 2030 00:00:00 GMT",
  "x-sbproxy-successor": "https://api.local/v2/"
}
```

## What this exercises

- `deprecation:` at forward-rule scope, overriding nothing and inherited by nothing: each rule announces only for itself
- RFC 9745 `Deprecation` (structured-field Date), RFC 8594 `Sunset` (HTTP-date), RFC 5829 `successor-version` and RFC 9745 `deprecation` Link relations
- `after_sunset: serve` (default) and `after_sunset: gone` (410 with the successor in the body)
- `sbproxy_deprecated_requests_total{origin, route, past_sunset, outcome}` usage tracking, and a `policy_violation` audit record with `event_type: api_deprecation` for each 410 refusal
- OpenAPI emission marking deprecated operations, via `expose_openapi: true`

## See also

- [docs/api-gateway.md](../../docs/api-gateway.md#deprecating-endpoints)
- [docs/configuration.md](../../docs/configuration.md#api-deprecation-rfc-9745--rfc-8594)
- [docs/openapi-emission.md](../../docs/openapi-emission.md)

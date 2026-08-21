# Problem-Details default renderer

*Last modified: 2026-08-21*

![Problem-Details default renderer](../../docs/assets/problem-details.gif)

The origin on `api.local` is protected by API key authentication and an
`ip_filter` policy. The operator authors a custom `error_pages` entry
for 401 and opts in to the RFC 9457 `application/problem+json` default
renderer for everything else via `problem_details:`.

The two blocks compose: per-status custom pages win when matched, and
the renderer catches every other error the proxy generates on this
origin with a structured body that downstream clients can introspect
without scraping prose. That is authentication denials (a bad or missing
API key, a failed JWT check), policy denials from the `policies:` chain
that do not write their own body (`ip_filter`, `waf`, `dlp`, `csrf`,
`rego`, and the rest), and upstream connection failures.

Denials whose body a protocol pins keep their own shape: the 429
rate-limit set, the AI-crawl payment family, and agent-to-agent chain
refusals. So does the 404 for a `Host` matching no origin, which is
answered before any origin config is resolved.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# 401 hits the custom error_pages entry (authored body wins).
curl -s -H 'Host: api.local' http://127.0.0.1:8080/get
# {"error":"unauthorized","hint":"set X-Api-Key"}

# Successful path: the upstream is reached when the API key is present.
curl -sv -H 'Host: api.local' -H 'X-Api-Key: secret-key' http://127.0.0.1:8080/get 2>&1 | grep '^< HTTP'
# < HTTP/1.1 200 OK
```

A policy denial has no authored page in this example, so it is the
renderer that answers. Policies run after authentication, so the call
below carries the API key and is refused by `ip_filter` on the
forwarded client IP:

```bash
curl -sv -H 'Host: api.local' -H 'X-Api-Key: secret-key' \
     -H 'X-Forwarded-For: 203.0.113.7' \
     http://127.0.0.1:8080/get 2>&1 | grep -E '^< HTTP|^< content-type|^\{'
# < HTTP/1.1 403 Forbidden
# < content-type: application/problem+json
# {"detail":"forbidden","instance":"/get","status":403,"title":"Forbidden","type":"https://api.example.com/errors/403"}
```

The keys come out sorted; formatted and reordered for reading, that body is:

```json
{
  "type": "https://api.example.com/errors/403",
  "title": "Forbidden",
  "status": 403,
  "detail": "forbidden",
  "instance": "/get"
}
```

Set `include_detail: false` and the `detail` field disappears. That is
the knob to reach for when a policy's own message would say more than
you want a client to see: the WAF, for instance, appends the id of the
rule that matched.

## What this exercises

- `problem_details.enabled: true` opt-in
- `problem_details.type_base_uri` stable `type` URIs
- `problem_details.include_detail: true` keeps the internal error
  string in the `detail` field (set to `false` to suppress it)
- Composition with `error_pages` per-status custom bodies
- Composition with `authentication.api_key`
- Composition with a `policies:` chain (`ip_filter`), whose denial the
  renderer shapes the same way it shapes an authentication denial

## See also

- [docs/configuration.md](../../docs/configuration.md)
- [examples/error-pages](../error-pages)
- RFC 9457: <https://www.rfc-editor.org/rfc/rfc9457.html>

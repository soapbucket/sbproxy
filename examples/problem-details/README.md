# Problem-Details default renderer

*Last modified: 2026-08-16*

![Problem-Details default renderer](../../docs/assets/problem-details.gif)

The origin on `api.local` is protected by API key authentication. The
operator authors a custom `error_pages` entry for 401 and opts in to the
RFC 9457 `application/problem+json` default renderer for everything else
via `problem_details:`.

The two blocks compose: per-status custom pages win when matched, and
the problem-details renderer catches every other authentication denial
on this origin (a bad or missing API key, a failed JWT check, and so
on) with a structured body that downstream clients can introspect
without scraping prose. It does not currently apply to policy denials
(`ip_filter`, `waf`, rate limiting, etc.) or to upstream-generated
errors; those keep their own response shapes.

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

When the `authentication` block on this origin denies a request with a
status code that does *not* match the `error_pages` table (this example
only authors a custom page for 401, so any other authentication failure
qualifies), the response body is rendered per RFC 9457 instead:

```json
{
  "type": "https://api.example.com/errors/403",
  "title": "Forbidden",
  "status": 403,
  "detail": "authentication failed",
  "instance": "/get"
}
```

## What this exercises

- `problem_details.enabled: true` opt-in
- `problem_details.type_base_uri` stable `type` URIs
- `problem_details.include_detail: true` keeps the internal error
  string in the `detail` field (set to `false` to suppress it)
- Composition with `error_pages` per-status custom bodies
- Composition with `authentication.api_key`

## See also

- [docs/configuration.md](../../docs/configuration.md)
- [examples/error-pages](../error-pages)
- RFC 9457: <https://www.rfc-editor.org/rfc/rfc9457.html>

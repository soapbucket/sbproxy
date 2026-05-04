# WAF (OWASP Core Rule Set)

*Last modified: 2026-04-27*

Demonstrates the `waf` policy with the OWASP Core Rule Set enabled. Each request is screened for common attack signatures (SQL injection, cross-site scripting, path traversal) before it reaches the `httpbin.org` upstream. With `action_on_match: block`, `test_mode: false`, and `fail_open: false`, any rule hit returns `403` synchronously and never forwards. Toggle `test_mode: true` to log matches without blocking, or set `action_on_match: log` for an alert-only deployment. The origin is selected by the `waf.local` Host header on `127.0.0.1:8080`.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Benign request - 200
$ curl -i -H 'Host: waf.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
...
```

```bash
# Classic SQL injection signature in the query string - 403
$ curl -i -H 'Host: waf.local' \
       "http://127.0.0.1:8080/get?id=1%27%20OR%20%271%27=%271"
HTTP/1.1 403 Forbidden
content-type: text/plain

blocked by waf
```

```bash
# Reflected XSS pattern - also blocked
$ curl -i -H 'Host: waf.local' \
       "http://127.0.0.1:8080/get?q=<script>alert(1)</script>"
HTTP/1.1 403 Forbidden
content-type: text/plain

blocked by waf
```

```bash
# Path traversal attempt - blocked
$ curl -i -H 'Host: waf.local' \
       "http://127.0.0.1:8080/get?file=../../../../etc/passwd"
HTTP/1.1 403 Forbidden
```

## What this exercises

- `waf` policy with `owasp_crs.enabled: true` covering the bundled CRS rule families
- `action_on_match: block` synchronous deny with a 403
- `fail_open: false` so the request is rejected, not allowed, if WAF evaluation cannot complete
- `test_mode: false` so matches are enforced rather than only logged

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

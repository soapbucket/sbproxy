# WAF (OWASP Core Rule Set)

*Last modified: 2026-04-27*

![WAF (OWASP Core Rule Set)](../../docs/assets/waf.gif)

Demonstrates the `waf` policy with its full 16-rule baseline: `owasp_crs.enabled: true` for the 4 built-in patterns and `owasp_crs.managed_bundle: true` for the 12-rule vendored CRS-derived bundle. The two flags are independent and neither implies the other, so `enabled` on its own gives you 4 rules rather than 16. Each request is screened for common attack signatures (SQL injection, cross-site scripting, path traversal, remote code execution, scanner fingerprints) before it reaches the `test.sbproxy.dev` upstream. With `action_on_match: block`, `test_mode: false`, and `failure_posture: closed`, any rule hit returns `403` synchronously and never forwards. Toggle `test_mode: true` to log matches without blocking, or set `action_on_match: log` for an alert-only deployment. The origin is selected by the `waf.local` Host header on `127.0.0.1:8080`.

## Run

```bash
sbproxy serve -f sb.yml
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

- `waf` policy with `owasp_crs.enabled: true` for the 4 built-in patterns
- `owasp_crs.managed_bundle: true` for the 12 vendored CRS-derived rules, which carry CRS-style ids (`crs-941-100`, `crs-942-100`, and so on) and cover XSS, SQLi, LFI, RFI, RCE, PHP and Node and Java injection, scanner detection, and protocol attack
- `paranoia` (unset here, so 1) gating all of them. Level 1 runs 8 of the 16 rules, level 2 runs 15, levels 3 and 4 run all 16
- `action_on_match: block` synchronous deny with a 403
- `failure_posture: closed` so the request is rejected, not allowed, if WAF evaluation cannot complete; the older `fail_open: false` spelling still parses and means the same thing (see [docs/degradation.md](../../docs/degradation.md) for the shared vocabulary)
- `test_mode: false` so matches are enforced rather than only logged

## See also

- [docs/waf-options.md](../../docs/waf-options.md) - what this baseline does not catch, why there is no SecLang engine in the proxy, and how to run a full OWASP CRS WAF in front of it
- [examples/waf-layered/](../waf-layered/) - the same policy inside an `ip_filter` + `ddos` + `dlp` stack
- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

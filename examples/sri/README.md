# Subresource Integrity (SRI) inspection

*Last modified: 2026-08-18*

![Subresource Integrity (SRI) inspection](../../docs/assets/sri.gif)

Demonstrates the `sri` policy in observation mode. The proxy walks `text/html` responses, inspects every `<script src="https://...">` and `<link rel="stylesheet" href="https://...">` pointing at an external origin, and checks for an `integrity="..."` attribute that uses one of the configured algorithms (`sha384` or `sha512` here). Missing or mismatched references are logged at warn level and counted in the `sbproxy_policy_triggers_total{policy_type="sri"}` metric. The proxy does not modify the body; SRI is a browser-side mechanism and the proxy's value is alerting an operator that a page is missing integrity coverage. Same-origin references and inline scripts are skipped per the SRI spec. The origin lives on `127.0.0.1:8080` behind the `sri.local` Host header and proxies to a small local fixture (`fixture.py`) serving one violating `<link>` and one compliant `<script>`. The scan runs on proxied responses and on generated (`static`/`mock`) ones alike; the proxied fixture here shows the realistic flow of auditing an upstream's pages.

## Run

```bash
# The upstream must be up first so it can serve the HTML sri.local proxies to.
python3 fixture.py &

sbproxy serve -f sb.yml
```

## Try it

```bash
# Fetch the canned HTML page. The proxy emits the body verbatim, but logs
# one SRI violation for the missing-integrity stylesheet.
$ curl -i -H 'Host: sri.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: text/html

<!doctype html>
<html>
  <head>
    <!-- This stylesheet has no integrity attribute. SRI logs a violation. -->
    <link rel="stylesheet" href="https://cdn.example.com/theme.css">
    <!-- This script has integrity. SRI is happy. -->
    <script src="https://cdn.example.com/lib.js"
            integrity="sha384-OLBgp1GsljhM2TJ-sbHjaiH9txEUvgdDTAzHv2P24donTt6_529l+9Ua0vFImLlb"
            crossorigin="anonymous"></script>
  </head>
  <body>
    <h1>SRI demo</h1>
  </body>
</html>
```

```bash
# Inspect the violation counter (admin API, basic auth):
$ curl -s -u admin:changeme http://127.0.0.1:9091/metrics | grep sbproxy_policy_triggers_total
sbproxy_policy_triggers_total{origin="sri.local",policy_type="sri",action="violation",agent_id="",agent_class=""} 1
```

```bash
# Proxy logs (stderr) include a structured warning per violating tag:
# WARN sbproxy_core::server::proxy_http: sri: subresource missing or weak integrity attribute hostname="sri.local" tag="link" url="https://cdn.example.com/theme.css" reason=MissingIntegrity
```

## What this exercises

- `sri` policy with `enforce: true` and the `sha384` / `sha512` algorithm allowlist
- Detection of missing `integrity` on cross-origin `<script>` and `<link rel="stylesheet">` tags
- Observation-only behaviour: the response body is unchanged and the response is not blocked
- Metrics integration via `sbproxy_policy_triggers_total{policy_type="sri"}`
- A `type: proxy` origin with a bundled fixture, so the audit runs against real upstream HTML (the scan also covers `static`/`mock` origins)

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

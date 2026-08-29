# GeoIP + User-Agent enrichment

*Last modified: 2026-08-22*

Two policies, `geoip` and `user_agent_parser`, resolve the client IP and parse the `User-Agent` header into structured data. Neither denies a request: each stamps its result onto `X-*` upstream headers and onto `sbproxy_plugin::RequestContextView` for any registered identity or anomaly hook. See [docs/request-enrichment.md](../../docs/request-enrichment.md).

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Ordinary desktop browser: no headless signal.
curl -s -H 'Host: api.local' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' \
  http://127.0.0.1:8080/get | jq '.headers["x-parsed-ua"] | fromjson'
# {"browser_name":"Chrome","browser_version":"120.0.0.0","os_name":"Windows","os_version":"10","device_type":"desktop","headless_library":null}

# Headless-automation client: headless_library populates.
curl -s -H 'Host: api.local' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.6099.109 Safari/537.36' \
  http://127.0.0.1:8080/get | jq '.headers["x-parsed-ua"] | fromjson | .headless_library'
# "headless_chrome"

# geoip runs with no database configured: no X-Geo-* headers, but the
# request still reaches the upstream (this OSS build's embedded MMDB
# is a zero-byte placeholder).
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.local' \
  -H 'X-Real-IP: 8.8.8.8' \
  http://127.0.0.1:8080/get
# 200

# A search-engine crawler is device_type "bot" but not headless_library:
curl -s -H 'Host: api.local' \
  -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
  http://127.0.0.1:8080/get | jq '.headers["x-parsed-ua"] | fromjson'
# {"browser_name":"","browser_version":"","os_name":"","os_version":"","device_type":"bot","headless_library":null}
```

Set `database_path:` in `sb.yml` to a real MaxMind GeoLite2 or IPinfo Lite `.mmdb` file to see `x-geo-country`, `x-geo-continent`, `x-geo-city`, and `x-geo-asn` on the same requests.

## What this exercises

- `policies[].type: geoip` and `policies[].type: user_agent_parser`
- `RequestContext::geo_lookup` / `RequestContext::parsed_user_agent`, read back into `sbproxy_plugin::RequestContextView` (`geo_country`, `geo_asn`, `ua_headless_library`)
- The `X-Geo-*` / `X-Parsed-Ua` upstream-header injection path, the same `trust_headers` mechanism `exposed_credentials` uses
- `headless_library` detection independent of generic bot classification

## See also

- [docs/request-enrichment.md](../../docs/request-enrichment.md)
- [docs/policy.md](../../docs/policy.md)
- [docs/headless-detection.md](../../docs/headless-detection.md)
- [docs/architecture.md](../../docs/architecture.md#signal-hooks-identity-classification-anomaly)
